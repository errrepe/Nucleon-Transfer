// Nucleon Transfer — String Catalog completeness (F8.4-U9, Swift Testing).
// Reads Resources/Localizable.xcstrings straight from the repo (SPM builds
// Core without resources): every key has a translated pt-BR value, format
// specifiers agree with the English source argument by argument, and the
// count strings carry plural variants. Also covers the pt-BR "(Erro N)"
// suffix in UserFacingError's pass-through check.
import Foundation
import Testing

@testable import NucleonTransfer

struct StringCatalogTests {
    /// Keys whose pt-BR text must vary by count even though English
    /// doesn't need inflection markup for them.
    static let pluralKeys: Set<String> = [
        "%lld active",
        "%lld failed",
        "%lld of %lld selected",
    ]

    static let catalogURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()       // NucleonTransferTests
        .deletingLastPathComponent()       // NucleonTransfer (project dir)
        .appendingPathComponent("NucleonTransfer/Resources/Localizable.xcstrings")

    private func loadStrings() throws -> [String: [String: Any]] {
        let data = try Data(contentsOf: Self.catalogURL)
        let root = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(root["sourceLanguage"] as? String == "en")
        return try #require(root["strings"] as? [String: [String: Any]])
    }

    @Test func catalogHasEveryKeyTranslatedToBrazilianPortuguese() throws {
        let strings = try loadStrings()
        #expect(strings.count > 200)
        for (key, entry) in strings {
            let pt = (entry["localizations"] as? [String: Any])?["pt-BR"] as? [String: Any]
            let forms = try #require(pt.map(Self.forms), "no pt-BR for \(key)")
            #expect(!forms.isEmpty, "no pt-BR value for \(key)")
            for form in forms {
                #expect(!form.value.isEmpty, "empty pt-BR value for \(key)")
                #expect(form.state == "translated", "pt-BR not translated: \(key)")
            }
        }
    }

    @Test func formatSpecifiersMatchEnglishArgumentByArgument() throws {
        let strings = try loadStrings()
        for (key, entry) in strings {
            let locs = entry["localizations"] as? [String: Any] ?? [:]
            let english = (locs["en"] as? [String: Any]).map(Self.forms) ?? []
            let englishValues = english.isEmpty ? [key] : english.map(\.value)
            let expected = Self.specifiers(key)
            for value in englishValues {
                #expect(Self.specifiers(value) == expected, "en specifiers differ: \(key) → \(value)")
            }
            let pt = (locs["pt-BR"] as? [String: Any]).map(Self.forms) ?? []
            for form in pt {
                #expect(Self.specifiers(form.value) == expected, "pt-BR specifiers differ: \(key) → \(form.value)")
            }
        }
    }

    @Test func countStringsHavePluralVariants() throws {
        let strings = try loadStrings()
        let inflected = strings.keys.filter { $0.contains("](inflect: true)") }
        #expect(inflected.count >= 5)
        for key in inflected + Array(Self.pluralKeys) {
            let locs = try #require(strings[key]?["localizations"] as? [String: Any], "missing \(key)")
            let languages = Self.pluralKeys.contains(key) ? ["pt-BR"] : ["en", "pt-BR"]
            for lang in languages {
                let loc = try #require(locs[lang] as? [String: Any], "\(lang) missing for \(key)")
                let categories = Self.pluralCategories(loc)
                #expect(categories.isSuperset(of: ["one", "other"]), "\(lang) plural variants for \(key): \(categories)")
            }
        }
    }

    @Test func localizedErrorSuffixPassesThroughUnchanged() {
        let pt = "Muitas tentativas recentes de início de sessão. (Erro 2028)"
        #expect(UserFacingError.message(forMessage: pt) == pt)
        let en = UserFacingError.rateLimited
        #expect(UserFacingError.message(forMessage: en) == en)
    }

    // MARK: - helpers

    struct Form {
        var value: String
        var state: String?
    }

    /// Every concrete string of one localization: the plain unit, each
    /// plural variant, and substitution strings expanded per variant.
    static func forms(_ loc: [String: Any]) -> [Form] {
        if let subs = loc["substitutions"] as? [String: [String: Any]],
           let unit = loc["stringUnit"] as? [String: Any],
           let template = unit["value"] as? String
        {
            var result: [Form] = []
            for (name, sub) in subs {
                let argNum = sub["argNum"] as? Int ?? 1
                let spec = sub["formatSpecifier"] as? String ?? "@"
                for variant in pluralForms(sub) {
                    let expanded = variant.value.replacingOccurrences(of: "%arg", with: "%\(argNum)$\(spec)")
                    let filled = template
                        .replacingOccurrences(of: "%\(argNum)$#@\(name)@", with: expanded)
                        .replacingOccurrences(of: "%#@\(name)@", with: expanded)
                    result.append(Form(value: filled, state: variant.state))
                }
            }
            return result
        }
        if let unit = loc["stringUnit"] as? [String: Any] {
            return [Form(value: unit["value"] as? String ?? "", state: unit["state"] as? String)]
        }
        return pluralForms(loc)
    }

    static func pluralForms(_ container: [String: Any]) -> [Form] {
        let plural = (container["variations"] as? [String: Any])?["plural"] as? [String: Any] ?? [:]
        return plural.values.compactMap { variant in
            guard let unit = (variant as? [String: Any])?["stringUnit"] as? [String: Any] else { return nil }
            return Form(value: unit["value"] as? String ?? "", state: unit["state"] as? String)
        }
    }

    static func pluralCategories(_ loc: [String: Any]) -> Set<String> {
        if let plural = (loc["variations"] as? [String: Any])?["plural"] as? [String: Any] {
            return Set(plural.keys)
        }
        let subs = loc["substitutions"] as? [String: [String: Any]] ?? [:]
        return subs.values.reduce(into: Set<String>()) { set, sub in
            let plural = (sub["variations"] as? [String: Any])?["plural"] as? [String: Any] ?? [:]
            set.formUnion(plural.keys)
        }
    }

    /// Argument position → conversion ("@", "lld", …). Positional
    /// specifiers keep their index; bare ones count up in order.
    static func specifiers(_ text: String) -> [Int: String] {
        var result: [Int: String] = [:]
        var next = 1
        let pattern = /%(?:(\d+)\$)?(@|lld|ld|d|lf|f|llu|lu|u)/
        for match in text.matches(of: pattern) {
            let position = match.1.flatMap { Int($0) } ?? next
            result[position] = String(match.2)
            if match.1 == nil { next += 1 }
        }
        return result
    }
}
