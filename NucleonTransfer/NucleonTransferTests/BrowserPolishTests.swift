// Nucleon Transfer — F8.4-U3 browser polish logic (Swift Testing).
// Back/Forward history, the selection subtitle, the Kind column text and
// the Finder-style relative Modified dates. Pure value logic.
import Foundation
import Testing

@testable import NucleonTransfer

struct ForwardStackTests {
    @Test func popRecordsForwardNearestFirst() {
        var history = ForwardStack<String>()
        history.record(from: ["A", "B", "C"], to: ["A"])
        #expect(history.next == "B")
        // Forward = push `next`: consumed, C stays.
        history.record(from: ["A"], to: ["A", "B"])
        #expect(history.next == "C")
        history.record(from: ["A", "B"], to: ["A", "B", "C"])
        #expect(!history.canGoForward)
    }

    @Test func singleBackThenForward() {
        var history = ForwardStack<String>()
        history.record(from: ["A"], to: [])
        #expect(history.next == "A")
        history.record(from: [], to: ["A"])
        #expect(history.next == nil)
    }

    @Test func newNavigationClearsForward() {
        var history = ForwardStack<String>()
        history.record(from: ["A", "B"], to: ["A"])
        history.record(from: ["A"], to: ["A", "X"])
        #expect(!history.canGoForward)
    }

    @Test func replacingThePathClearsForward() {
        var history = ForwardStack<String>()
        history.record(from: ["A", "B"], to: ["A"])
        history.record(from: ["A"], to: ["Z", "Y"])
        #expect(!history.canGoForward)
    }

    @Test func unchangedPathKeepsHistory() {
        var history = ForwardStack<String>()
        history.record(from: ["A", "B"], to: ["A"])
        history.record(from: ["A"], to: ["A"])
        #expect(history.next == "B")
    }

    @Test func successivePopsStack() {
        var history = ForwardStack<String>()
        history.record(from: ["A", "B", "C"], to: ["A", "B"])
        history.record(from: ["A", "B"], to: ["A"])
        #expect(history.items == ["C", "B"])
    }
}

struct SelectionSubtitleTests {
    @Test func noSelectionShowsItemCount() {
        #expect(DriveFormatting.subtitle(selected: 0, total: 14) == "14 items")
        #expect(DriveFormatting.subtitle(selected: 0, total: 1) == "1 item")
    }

    @Test func selectionShowsOfTotal() {
        #expect(DriveFormatting.subtitle(selected: 2, total: 14) == "2 of 14 selected")
    }

    @Test func selectionNeverExceedsTotal() {
        #expect(DriveFormatting.subtitle(selected: 5, total: 3) == "3 of 3 selected")
    }
}

struct ItemKindDescriptionTests {
    private let table = ["pdf": "PDF document", "heic": "HEIF image"]

    @Test func foldersReadFolder() {
        #expect(ItemKindDescription.describe(isFolder: true, fileExtension: "pdf") { table[$0] } == "Folder")
    }

    @Test func knownExtensionUsesLookup() {
        #expect(ItemKindDescription.describe(isFolder: false, fileExtension: "PDF") { table[$0] } == "PDF document")
    }

    @Test func unknownOrMissingExtensionIsDocument() {
        #expect(ItemKindDescription.describe(isFolder: false, fileExtension: "zzz") { table[$0] } == "Document")
        #expect(ItemKindDescription.describe(isFolder: false, fileExtension: "") { _ in "never" } == "Document")
        #expect(ItemKindDescription.describe(isFolder: false, fileExtension: "x") { _ in "" } == "Document")
    }
}

struct ModifiedDateFormattingTests {
    private var calendar: Calendar {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC") ?? .gmt
        return cal
    }

    private let locale = Locale(identifier: "en_US")
    /// 2026-10-04 15:00 UTC.
    private let now = Date(timeIntervalSince1970: 1_791_126_000)

    @Test func styleBuckets() {
        let cal = calendar
        #expect(ModifiedDateFormatting.style(for: now.addingTimeInterval(-3_600), now: now, calendar: cal) == .today)
        #expect(ModifiedDateFormatting.style(for: now.addingTimeInterval(-86_400), now: now, calendar: cal) == .yesterday)
        #expect(ModifiedDateFormatting.style(for: now.addingTimeInterval(-3 * 86_400), now: now, calendar: cal) == .absolute)
        // Clock skew: a future date is never "Today".
        #expect(ModifiedDateFormatting.style(for: now.addingTimeInterval(60), now: now, calendar: cal) == .absolute)
    }

    @Test func todayAndYesterdayReadLikeFinder() {
        let today = ModifiedDateFormatting.string(
            for: now.addingTimeInterval(-3_600), now: now, calendar: calendar, locale: locale
        )
        let yesterday = ModifiedDateFormatting.string(
            for: now.addingTimeInterval(-86_400), now: now, calendar: calendar, locale: locale
        )
        #expect(today.hasPrefix("Today at "))
        #expect(today.contains("2:00"))
        #expect(yesterday.hasPrefix("Yesterday at "))
        #expect(yesterday.contains("3:00"))
    }

    @Test func olderDatesAreAbsolute() {
        let old = ModifiedDateFormatting.string(
            for: now.addingTimeInterval(-30 * 86_400), now: now, calendar: calendar, locale: locale
        )
        #expect(old.contains("2026"))
        #expect(!old.contains("Today") && !old.contains("Yesterday"))
    }
}
