// Nucleon Transfer — the browser's "Modified" column text (F8.4-U3).
// Finder style: "Today at 14:32", "Yesterday at 09:10", otherwise the
// absolute date + time. The day word comes from RelativeDateTimeFormatter
// (.named, sentence-start capitalization) so it localizes with the system;
// dates in the future (clock skew) always read absolute.
import Foundation

enum ModifiedDateFormatting {
    enum Style: Equatable, Sendable {
        case today, yesterday, absolute
    }

    /// Which presentation `date` gets relative to `now`.
    static func style(for date: Date, now: Date, calendar: Calendar) -> Style {
        guard date <= now else { return .absolute }
        if calendar.isDate(date, inSameDayAs: now) { return .today }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now),
           calendar.isDate(date, inSameDayAs: yesterday) {
            return .yesterday
        }
        return .absolute
    }

    static func string(
        for date: Date,
        now: Date = .now,
        calendar: Calendar = .autoupdatingCurrent,
        locale: Locale = .autoupdatingCurrent
    ) -> String {
        var absolute = Date.FormatStyle(date: .abbreviated, time: .shortened)
        absolute.calendar = calendar
        absolute.timeZone = calendar.timeZone
        absolute.locale = locale
        let style = style(for: date, now: now, calendar: calendar)
        guard style != .absolute else { return date.formatted(absolute) }

        var timeOnly = Date.FormatStyle(date: .omitted, time: .shortened)
        timeOnly.calendar = calendar
        timeOnly.timeZone = calendar.timeZone
        timeOnly.locale = locale
        let time = date.formatted(timeOnly)

        let relative = RelativeDateTimeFormatter()
        relative.dateTimeStyle = .named
        relative.formattingContext = .beginningOfSentence
        relative.locale = locale
        relative.calendar = calendar
        let day = relative.localizedString(from: DateComponents(day: style == .today ? 0 : -1))
        return String(localized: "\(day) at \(time)", comment: "Modified column: “Today at 14:32”")
    }
}
