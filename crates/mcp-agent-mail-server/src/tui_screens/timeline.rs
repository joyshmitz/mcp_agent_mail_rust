//! Chronological timeline pane with dense navigation affordances.
//!
//! [`TimelinePane`] provides a cursor-based, scrollable event timeline
//! designed for deep diagnosis.  It renders each event as a compact row
//! with sequence number, timestamp, source badge, icon, and summary,
//! and exposes cursor position so a parent screen can render an
//! inspector detail panel alongside.

use std::collections::HashSet;

use ftui::layout::Rect;
use ftui::widgets::Widget;
use ftui::widgets::block::Block;
use ftui::widgets::borders::BorderType;
use ftui::widgets::paragraph::Paragraph;
use ftui::{Event, Frame, KeyCode, KeyEventKind};
use ftui_runtime::program::Cmd;

use crate::tui_bridge::TuiSharedState;
use crate::tui_events::{EventSeverity, EventSource, MailEvent, MailEventKind, VerbosityTier};
use crate::tui_screens::{DeepLinkTarget, HelpEntry, MailScreen, MailScreenMsg};

// Re-use dashboard formatting helpers.
use super::dashboard::{EventEntry, format_event};

// ──────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────

/// Max event entries retained in the timeline scroll-back.
const TIMELINE_CAPACITY: usize = 5000;

/// Page-up/down scroll amount in lines.
const PAGE_SIZE: usize = 20;

// ──────────────────────────────────────────────────────────────────────
// TimelinePane
// ──────────────────────────────────────────────────────────────────────

/// A cursor-based, filterable, chronological event timeline.
///
/// Unlike the dashboard event log (scroll-offset based, auto-follow),
/// the timeline uses an explicit cursor position for event selection,
/// and defaults to *not* auto-following so the operator can inspect
/// historical events.
pub struct TimelinePane {
    /// All ingested event entries.
    entries: Vec<TimelineEntry>,
    /// Last consumed sequence number.
    last_seq: u64,
    /// Cursor position in the *filtered* view (0 = first visible entry).
    cursor: usize,
    /// Whether the cursor tracks new events automatically.
    follow: bool,
    /// Kind filter (empty = show all).
    kind_filter: HashSet<MailEventKind>,
    /// Source filter (empty = show all).
    source_filter: HashSet<EventSource>,
    /// Verbosity tier controlling minimum severity shown.
    verbosity: VerbosityTier,
    /// Total events ingested (including trimmed).
    total_ingested: u64,
}

/// Extended entry that retains the raw event for inspector access.
#[derive(Debug, Clone)]
pub(crate) struct TimelineEntry {
    /// Formatted display entry.
    pub display: EventEntry,
    /// Raw sequence number.
    pub seq: u64,
    /// Raw timestamp (microseconds).
    pub timestamp_micros: i64,
    /// Event source (for source filtering).
    pub source: EventSource,
    /// Derived severity (for verbosity filtering).
    pub severity: EventSeverity,
    /// Raw event for the inspector detail panel (br-10wc.7.2).
    pub raw: MailEvent,
}

impl TimelinePane {
    /// Create a new empty timeline pane.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(TIMELINE_CAPACITY),
            last_seq: 0,
            cursor: 0,
            follow: false,
            kind_filter: HashSet::new(),
            source_filter: HashSet::new(),
            verbosity: VerbosityTier::default(),
            total_ingested: 0,
        }
    }

    /// Ingest new events from the shared state ring buffer.
    pub fn ingest(&mut self, state: &TuiSharedState) {
        let new_events = state.events_since(self.last_seq);
        for event in &new_events {
            self.last_seq = event.seq().max(self.last_seq);
            self.total_ingested += 1;
            self.entries.push(TimelineEntry {
                display: format_event(event),
                seq: event.seq(),
                timestamp_micros: event.timestamp_micros(),
                source: event.source(),
                severity: event.severity(),
                raw: event.clone(),
            });
        }
        // Trim to capacity.
        if self.entries.len() > TIMELINE_CAPACITY {
            let excess = self.entries.len() - TIMELINE_CAPACITY;
            self.entries.drain(..excess);
            // Adjust cursor if it pointed at drained entries.
            self.cursor = self.cursor.saturating_sub(excess);
        }
        // Auto-follow: move cursor to end.
        if self.follow && !new_events.is_empty() {
            let filtered_len = self.filtered_len();
            if filtered_len > 0 {
                self.cursor = filtered_len - 1;
            }
        }
    }

    /// Return the currently selected raw event (if any).
    #[must_use]
    pub fn selected_event(&self) -> Option<&MailEvent> {
        let filtered = self.filtered_entries();
        filtered.get(self.cursor).map(|e| &e.raw)
    }

    /// Return the currently selected timeline entry (if any).
    ///
    /// Pre-wired for the inspector panel (br-10wc.7.2).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn selected_entry(&self) -> Option<&TimelineEntry> {
        let filtered = self.filtered_entries();
        filtered.into_iter().nth(self.cursor)
    }

    /// Cursor position in the filtered view.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether follow mode is active.
    #[must_use]
    pub const fn follow(&self) -> bool {
        self.follow
    }

    /// Toggle a kind filter on/off.
    pub fn toggle_kind_filter(&mut self, kind: MailEventKind) {
        if self.kind_filter.contains(&kind) {
            self.kind_filter.remove(&kind);
        } else {
            self.kind_filter.insert(kind);
        }
        self.clamp_cursor();
    }

    /// Toggle a source filter on/off.
    pub fn toggle_source_filter(&mut self, source: EventSource) {
        if self.source_filter.contains(&source) {
            self.source_filter.remove(&source);
        } else {
            self.source_filter.insert(source);
        }
        self.clamp_cursor();
    }

    /// Clear all filters and reset verbosity to default.
    pub fn clear_filters(&mut self) {
        self.kind_filter.clear();
        self.source_filter.clear();
        self.verbosity = VerbosityTier::default();
        self.clamp_cursor();
    }

    /// Jump to the entry closest to the given timestamp (microseconds).
    pub fn jump_to_time(&mut self, target_micros: i64) {
        let filtered = self.filtered_entries();
        if filtered.is_empty() {
            return;
        }
        // Binary search for closest entry.
        let idx = filtered
            .binary_search_by_key(&target_micros, |e| e.timestamp_micros)
            .unwrap_or_else(|i| i.min(filtered.len() - 1));
        self.cursor = idx;
        self.follow = false;
    }

    /// Move cursor up by `n` lines.
    pub const fn cursor_up(&mut self, n: usize) {
        self.cursor = self.cursor.saturating_sub(n);
        self.follow = false;
    }

    /// Move cursor down by `n` lines.
    pub fn cursor_down(&mut self, n: usize) {
        let max = self.filtered_len().saturating_sub(1);
        self.cursor = (self.cursor + n).min(max);
    }

    /// Jump to first entry.
    pub const fn cursor_home(&mut self) {
        self.cursor = 0;
        self.follow = false;
    }

    /// Jump to last entry.
    pub fn cursor_end(&mut self) {
        let max = self.filtered_len().saturating_sub(1);
        self.cursor = max;
    }

    /// Toggle follow mode.
    pub fn toggle_follow(&mut self) {
        self.follow = !self.follow;
        if self.follow {
            self.cursor_end();
        }
    }

    // ── Internal helpers ────────────────────────────────────────────

    fn filtered_entries(&self) -> Vec<&TimelineEntry> {
        self.entries
            .iter()
            .filter(|e| {
                self.verbosity.includes(e.severity)
                    && (self.kind_filter.is_empty() || self.kind_filter.contains(&e.display.kind))
                    && (self.source_filter.is_empty() || self.source_filter.contains(&e.source))
            })
            .collect()
    }

    fn filtered_len(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| {
                self.verbosity.includes(e.severity)
                    && (self.kind_filter.is_empty() || self.kind_filter.contains(&e.display.kind))
                    && (self.source_filter.is_empty() || self.source_filter.contains(&e.source))
            })
            .count()
    }

    fn clamp_cursor(&mut self) {
        let max = self.filtered_len().saturating_sub(1);
        self.cursor = self.cursor.min(max);
    }
}

impl Default for TimelinePane {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────
// TimelineScreen — wraps TimelinePane as a full MailScreen
// ──────────────────────────────────────────────────────────────────────

/// A full TUI screen backed by [`TimelinePane`].
///
/// This provides the "Messages" tab experience: a scrollable
/// timeline with cursor-based selection and an inspector detail pane.
pub struct TimelineScreen {
    pane: TimelinePane,
    /// Whether the inspector panel is visible (toggled with Enter/i).
    inspector_visible: bool,
}

impl TimelineScreen {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pane: TimelinePane::new(),
            inspector_visible: true,
        }
    }
}

impl Default for TimelineScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl MailScreen for TimelineScreen {
    fn update(&mut self, event: &Event, _state: &TuiSharedState) -> Cmd<MailScreenMsg> {
        if let Event::Key(key) = event {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    // Cursor navigation
                    KeyCode::Char('j') | KeyCode::Down => self.pane.cursor_down(1),
                    KeyCode::Char('k') | KeyCode::Up => self.pane.cursor_up(1),
                    KeyCode::PageDown | KeyCode::Char('d') => {
                        self.pane.cursor_down(PAGE_SIZE);
                    }
                    KeyCode::PageUp | KeyCode::Char('u') => {
                        self.pane.cursor_up(PAGE_SIZE);
                    }
                    KeyCode::Char('G') | KeyCode::End => self.pane.cursor_end(),
                    KeyCode::Char('g') | KeyCode::Home => self.pane.cursor_home(),

                    // Follow mode
                    KeyCode::Char('f') => self.pane.toggle_follow(),

                    // Cycle verbosity tier
                    KeyCode::Char('v') => {
                        self.pane.verbosity = self.pane.verbosity.next();
                        self.pane.clamp_cursor();
                    }

                    // Cycle kind filter
                    KeyCode::Char('t') => {
                        cycle_kind_filter(&mut self.pane.kind_filter);
                        self.pane.clamp_cursor();
                    }

                    // Cycle source filter
                    KeyCode::Char('s') => {
                        cycle_source_filter(&mut self.pane.source_filter);
                        self.pane.clamp_cursor();
                    }

                    // Clear all filters
                    KeyCode::Char('c') => self.pane.clear_filters(),

                    // Toggle inspector panel
                    KeyCode::Char('i') | KeyCode::Enter => {
                        self.inspector_visible = !self.inspector_visible;
                    }

                    _ => {}
                }
            }
        }
        Cmd::None
    }

    fn tick(&mut self, _tick_count: u64, state: &TuiSharedState) {
        self.pane.ingest(state);
    }

    fn receive_deep_link(&mut self, target: &DeepLinkTarget) -> bool {
        match target {
            DeepLinkTarget::TimelineAtTime(micros) => {
                self.pane.jump_to_time(*micros);
                self.inspector_visible = true;
                true
            }
            _ => false,
        }
    }

    fn view(&self, frame: &mut Frame<'_>, area: Rect, _state: &TuiSharedState) {
        if self.inspector_visible && area.width >= 60 {
            // Split: 60% timeline, 40% inspector.
            let split = area.width * 3 / 5;
            let timeline_area = Rect::new(area.x, area.y, split, area.height);
            let inspector_area = Rect::new(
                area.x + split,
                area.y,
                area.width.saturating_sub(split),
                area.height,
            );
            render_timeline(frame, timeline_area, &self.pane);
            super::inspector::render_inspector(frame, inspector_area, self.pane.selected_event());
        } else {
            render_timeline(frame, area, &self.pane);
        }
    }

    fn keybindings(&self) -> Vec<HelpEntry> {
        vec![
            HelpEntry {
                key: "j/k",
                action: "Move cursor",
            },
            HelpEntry {
                key: "d/u",
                action: "Page down/up",
            },
            HelpEntry {
                key: "G/g",
                action: "End / Home",
            },
            HelpEntry {
                key: "f",
                action: "Toggle follow",
            },
            HelpEntry {
                key: "v",
                action: "Cycle verbosity tier",
            },
            HelpEntry {
                key: "t",
                action: "Cycle kind filter",
            },
            HelpEntry {
                key: "s",
                action: "Cycle source filter",
            },
            HelpEntry {
                key: "c",
                action: "Clear all filters",
            },
            HelpEntry {
                key: "i/Enter",
                action: "Toggle inspector",
            },
        ]
    }

    fn title(&self) -> &'static str {
        "Event Timeline"
    }

    fn tab_label(&self) -> &'static str {
        "Timeline"
    }
}

// ──────────────────────────────────────────────────────────────────────
// Filter cycling
// ──────────────────────────────────────────────────────────────────────

/// Cycle kind filter: empty → Tool → Message → Http → Reservation → clear.
fn cycle_kind_filter(filter: &mut HashSet<MailEventKind>) {
    if filter.is_empty() {
        filter.insert(MailEventKind::ToolCallStart);
        filter.insert(MailEventKind::ToolCallEnd);
    } else if filter.contains(&MailEventKind::ToolCallEnd) {
        filter.clear();
        filter.insert(MailEventKind::MessageSent);
        filter.insert(MailEventKind::MessageReceived);
    } else if filter.contains(&MailEventKind::MessageSent) {
        filter.clear();
        filter.insert(MailEventKind::HttpRequest);
    } else if filter.contains(&MailEventKind::HttpRequest) {
        filter.clear();
        filter.insert(MailEventKind::ReservationGranted);
        filter.insert(MailEventKind::ReservationReleased);
    } else {
        filter.clear();
    }
}

/// Cycle source filter: empty → Tooling → Http → Mail → clear.
fn cycle_source_filter(filter: &mut HashSet<EventSource>) {
    if filter.is_empty() {
        filter.insert(EventSource::Tooling);
    } else if filter.contains(&EventSource::Tooling) {
        filter.clear();
        filter.insert(EventSource::Http);
    } else if filter.contains(&EventSource::Http) {
        filter.clear();
        filter.insert(EventSource::Mail);
    } else if filter.contains(&EventSource::Mail) {
        filter.clear();
        filter.insert(EventSource::Reservations);
    } else {
        filter.clear();
    }
}

// ──────────────────────────────────────────────────────────────────────
// Rendering
// ──────────────────────────────────────────────────────────────────────

/// Source badge abbreviation.
const fn source_badge(src: EventSource) -> &'static str {
    match src {
        EventSource::Tooling => "TOOL",
        EventSource::Http => "HTTP",
        EventSource::Mail => "MAIL",
        EventSource::Reservations => "RESV",
        EventSource::Lifecycle => "LIFE",
        EventSource::Database => "DB  ",
        EventSource::Unknown => "????",
    }
}

/// Render the timeline pane into the given area.
fn render_timeline(frame: &mut Frame<'_>, area: Rect, pane: &TimelinePane) {
    let inner_height = area.height.saturating_sub(2) as usize; // borders
    if inner_height == 0 {
        return;
    }

    let filtered = pane.filtered_entries();
    let total = filtered.len();
    let cursor = pane.cursor.min(total.saturating_sub(1));

    // Compute viewport so cursor is always visible.
    let (start, end) = viewport_range(total, inner_height, cursor);
    let viewport = &filtered[start..end];

    // Build text lines with severity badge.
    let mut lines = Vec::with_capacity(viewport.len());
    for (view_idx, entry) in viewport.iter().enumerate() {
        let abs_idx = start + view_idx;
        let marker = if abs_idx == cursor { '>' } else { ' ' };
        let src_badge = source_badge(entry.source);
        let sev_badge = entry.severity.badge();
        lines.push(format!(
            "{marker} {:>6} {} {sev_badge} [{src_badge}] {} {}",
            entry.seq, entry.display.timestamp, entry.display.icon, entry.display.summary,
        ));
    }
    let text = lines.join("\n");

    // Title with position info.
    let pos = if total == 0 {
        "empty".to_string()
    } else {
        format!("{}/{total}", cursor + 1)
    };
    let follow_tag = if pane.follow { " [FOLLOW]" } else { "" };
    let verbosity_tag = format!(" [{}]", pane.verbosity.label());
    let filter_tag = build_filter_tag(&pane.kind_filter, &pane.source_filter);
    let title = format!("Timeline ({pos}){follow_tag}{verbosity_tag}{filter_tag}");

    let block = Block::default()
        .title(&title)
        .border_type(BorderType::Rounded);
    let p = Paragraph::new(text).block(block);
    p.render(area, frame);
}

/// Compute the viewport [start, end) to keep cursor visible.
fn viewport_range(total: usize, height: usize, cursor: usize) -> (usize, usize) {
    if total <= height {
        return (0, total);
    }
    // Keep cursor roughly centered, but clamp to bounds.
    let half = height / 2;
    let ideal_start = cursor.saturating_sub(half);
    let start = ideal_start.min(total - height);
    let end = (start + height).min(total);
    (start, end)
}

/// Build a compact filter tag string.
fn build_filter_tag(
    kind_filter: &HashSet<MailEventKind>,
    source_filter: &HashSet<EventSource>,
) -> String {
    let mut parts = Vec::new();
    if !kind_filter.is_empty() {
        let kinds: Vec<_> = kind_filter.iter().map(|k| format!("{k:?}")).collect();
        parts.push(format!("kind:{}", kinds.join(",")));
    }
    if !source_filter.is_empty() {
        let sources: Vec<_> = source_filter.iter().map(|s| format!("{s:?}")).collect();
        parts.push(format!("src:{}", sources.join(",")));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", parts.join(" "))
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(_seq: u64) -> MailEvent {
        MailEvent::http_request("GET", "/test", 200, 10, "127.0.0.1")
    }

    /// Create a pane with All verbosity so Debug-level test entries are visible.
    fn test_pane() -> TimelinePane {
        let mut pane = TimelinePane::new();
        pane.verbosity = VerbosityTier::All;
        pane
    }

    #[test]
    fn new_pane_is_empty() {
        let pane = TimelinePane::new();
        assert_eq!(pane.entries.len(), 0);
        assert_eq!(pane.cursor, 0);
        assert!(!pane.follow);
        assert!(pane.selected_event().is_none());
    }

    #[test]
    fn cursor_navigation() {
        let mut pane = test_pane();
        // Manually push entries.
        for i in 0..10 {
            pane.entries.push(TimelineEntry {
                display: format_event(&make_event(i)),
                seq: i,
                timestamp_micros: i64::try_from(i)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000),
                source: EventSource::Http,
                severity: EventSeverity::Debug,
                raw: make_event(i),
            });
        }
        assert_eq!(pane.cursor, 0);

        pane.cursor_down(3);
        assert_eq!(pane.cursor, 3);

        pane.cursor_up(1);
        assert_eq!(pane.cursor, 2);

        pane.cursor_end();
        assert_eq!(pane.cursor, 9);

        pane.cursor_home();
        assert_eq!(pane.cursor, 0);
    }

    #[test]
    fn cursor_clamps_at_bounds() {
        let mut pane = test_pane();
        for i in 0..5 {
            pane.entries.push(TimelineEntry {
                display: format_event(&make_event(i)),
                seq: i,
                timestamp_micros: i64::try_from(i)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000),
                source: EventSource::Http,
                severity: EventSeverity::Debug,
                raw: make_event(i),
            });
        }

        pane.cursor_down(100);
        assert_eq!(pane.cursor, 4);

        pane.cursor_up(100);
        assert_eq!(pane.cursor, 0);
    }

    #[test]
    fn follow_mode_tracks_end() {
        let mut pane = test_pane();
        pane.follow = true;

        let state = TuiSharedState::new(&mcp_agent_mail_core::Config::default());
        let _ = state.push_event(MailEvent::http_request("GET", "/a", 200, 5, "127.0.0.1"));
        pane.ingest(&state);
        assert_eq!(pane.cursor, 0); // First entry, idx 0.

        let _ = state.push_event(MailEvent::http_request("POST", "/b", 201, 3, "127.0.0.1"));
        pane.ingest(&state);
        assert_eq!(pane.cursor, 1); // Followed to end.
    }

    #[test]
    fn kind_filter_restricts_view() {
        let mut pane = test_pane();
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::HttpRequest,
                severity: crate::tui_events::EventSeverity::Debug,
                timestamp: "00:00:00.000".to_string(),
                icon: '↔',
                summary: "GET /x".to_string(),
            },
            seq: 1,
            timestamp_micros: 1_000_000,
            source: EventSource::Http,
            severity: EventSeverity::Debug,
            raw: make_event(1),
        });
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::MessageSent,
                severity: crate::tui_events::EventSeverity::Info,
                timestamp: "00:00:01.000".to_string(),
                icon: '✉',
                summary: "msg sent".to_string(),
            },
            seq: 2,
            timestamp_micros: 2_000_000,
            source: EventSource::Mail,
            severity: EventSeverity::Info,
            raw: make_event(2),
        });

        assert_eq!(pane.filtered_len(), 2);

        pane.toggle_kind_filter(MailEventKind::HttpRequest);
        assert_eq!(pane.filtered_len(), 1);

        pane.toggle_kind_filter(MailEventKind::HttpRequest);
        assert_eq!(pane.filtered_len(), 2);
    }

    #[test]
    fn source_filter_restricts_view() {
        let mut pane = test_pane();
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::HttpRequest,
                severity: crate::tui_events::EventSeverity::Debug,
                timestamp: "00:00:00.000".to_string(),
                icon: '↔',
                summary: "GET /x".to_string(),
            },
            seq: 1,
            timestamp_micros: 1_000_000,
            source: EventSource::Http,
            severity: EventSeverity::Debug,
            raw: make_event(1),
        });
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::ToolCallEnd,
                severity: crate::tui_events::EventSeverity::Debug,
                timestamp: "00:00:01.000".to_string(),
                icon: '⚙',
                summary: "tool done".to_string(),
            },
            seq: 2,
            timestamp_micros: 2_000_000,
            source: EventSource::Tooling,
            severity: EventSeverity::Debug,
            raw: make_event(2),
        });

        pane.toggle_source_filter(EventSource::Http);
        assert_eq!(pane.filtered_len(), 1);

        pane.clear_filters();
        // `clear_filters` also resets verbosity to default (Standard),
        // which hides Debug rows in this fixture.
        assert_eq!(pane.filtered_len(), 0);
        assert_eq!(pane.verbosity, VerbosityTier::default());
    }

    #[test]
    fn jump_to_time_positions_cursor() {
        let mut pane = test_pane();
        for i in 0..100 {
            pane.entries.push(TimelineEntry {
                display: format_event(&make_event(i)),
                seq: i,
                timestamp_micros: i64::try_from(i)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000),
                source: EventSource::Http,
                severity: EventSeverity::Debug,
                raw: make_event(i),
            });
        }

        pane.jump_to_time(50_000_000); // 50 seconds.
        assert_eq!(pane.cursor, 50);
        assert!(!pane.follow);

        pane.jump_to_time(999_000_000); // Beyond last.
        assert_eq!(pane.cursor, 99);
    }

    #[test]
    fn viewport_range_small_list() {
        let (start, end) = viewport_range(5, 20, 3);
        assert_eq!(start, 0);
        assert_eq!(end, 5);
    }

    #[test]
    fn viewport_range_keeps_cursor_visible() {
        // 100 entries, 20 visible, cursor at 80.
        let (start, end) = viewport_range(100, 20, 80);
        assert!(start <= 80);
        assert!(end > 80);
        assert_eq!(end - start, 20);
    }

    #[test]
    fn viewport_range_cursor_at_start() {
        let (start, end) = viewport_range(100, 20, 0);
        assert_eq!(start, 0);
        assert_eq!(end, 20);
    }

    #[test]
    fn viewport_range_cursor_at_end() {
        let (start, end) = viewport_range(100, 20, 99);
        assert_eq!(start, 80);
        assert_eq!(end, 100);
    }

    #[test]
    fn source_badge_values() {
        assert_eq!(source_badge(EventSource::Tooling), "TOOL");
        assert_eq!(source_badge(EventSource::Http), "HTTP");
        assert_eq!(source_badge(EventSource::Mail), "MAIL");
        assert_eq!(source_badge(EventSource::Reservations), "RESV");
        assert_eq!(source_badge(EventSource::Lifecycle), "LIFE");
        assert_eq!(source_badge(EventSource::Database), "DB  ");
        assert_eq!(source_badge(EventSource::Unknown), "????");
    }

    #[test]
    fn build_filter_tag_empty() {
        let tag = build_filter_tag(&HashSet::new(), &HashSet::new());
        assert!(tag.is_empty());
    }

    #[test]
    fn build_filter_tag_with_kind() {
        let mut kinds = HashSet::new();
        kinds.insert(MailEventKind::HttpRequest);
        let tag = build_filter_tag(&kinds, &HashSet::new());
        assert!(tag.contains("kind:"));
        assert!(tag.contains("HttpRequest"));
    }

    #[test]
    fn cycle_kind_filter_round_trips() {
        let mut filter = HashSet::new();
        // empty → Tool
        cycle_kind_filter(&mut filter);
        assert!(filter.contains(&MailEventKind::ToolCallEnd));
        // Tool → Message
        cycle_kind_filter(&mut filter);
        assert!(filter.contains(&MailEventKind::MessageSent));
        // Message → Http
        cycle_kind_filter(&mut filter);
        assert!(filter.contains(&MailEventKind::HttpRequest));
        // Http → Reservation
        cycle_kind_filter(&mut filter);
        assert!(filter.contains(&MailEventKind::ReservationGranted));
        // Reservation → clear
        cycle_kind_filter(&mut filter);
        assert!(filter.is_empty());
    }

    #[test]
    fn cycle_source_filter_round_trips() {
        let mut filter = HashSet::new();
        cycle_source_filter(&mut filter);
        assert!(filter.contains(&EventSource::Tooling));
        cycle_source_filter(&mut filter);
        assert!(filter.contains(&EventSource::Http));
        cycle_source_filter(&mut filter);
        assert!(filter.contains(&EventSource::Mail));
        cycle_source_filter(&mut filter);
        assert!(filter.contains(&EventSource::Reservations));
        cycle_source_filter(&mut filter);
        assert!(filter.is_empty());
    }

    #[test]
    fn render_timeline_no_panic_empty() {
        let pane = TimelinePane::new();
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(80, 24, &mut pool);
        render_timeline(&mut frame, Rect::new(0, 0, 80, 24), &pane);
    }

    #[test]
    fn render_timeline_no_panic_with_entries() {
        let mut pane = TimelinePane::new();
        for i in 0..50 {
            pane.entries.push(TimelineEntry {
                display: format_event(&make_event(i)),
                seq: i,
                timestamp_micros: i64::try_from(i)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000),
                source: EventSource::Http,
                severity: EventSeverity::Debug,
                raw: make_event(i),
            });
        }
        pane.cursor = 25;

        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(120, 30, &mut pool);
        render_timeline(&mut frame, Rect::new(0, 0, 120, 30), &pane);
    }

    #[test]
    fn render_timeline_minimum_size() {
        let pane = TimelinePane::new();
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(40, 5, &mut pool);
        render_timeline(&mut frame, Rect::new(0, 0, 40, 5), &pane);
    }

    #[test]
    fn trim_to_capacity() {
        let mut pane = TimelinePane::new();
        // Push more than TIMELINE_CAPACITY entries.
        for i in 0..(TIMELINE_CAPACITY + 100) {
            pane.entries.push(TimelineEntry {
                display: format_event(&make_event(i as u64)),
                seq: i as u64,
                timestamp_micros: i64::try_from(i)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000),
                source: EventSource::Http,
                severity: EventSeverity::Debug,
                raw: make_event(i as u64),
            });
        }
        pane.cursor = TIMELINE_CAPACITY + 50;

        // Simulate trim logic.
        if pane.entries.len() > TIMELINE_CAPACITY {
            let excess = pane.entries.len() - TIMELINE_CAPACITY;
            pane.entries.drain(..excess);
            pane.cursor = pane.cursor.saturating_sub(excess);
        }

        assert_eq!(pane.entries.len(), TIMELINE_CAPACITY);
        assert!(pane.cursor < TIMELINE_CAPACITY);
    }

    #[test]
    fn selected_event_returns_correct_entry() {
        let mut pane = test_pane();
        let event = MailEvent::http_request("DELETE", "/api/test", 204, 42, "127.0.0.1");
        pane.entries.push(TimelineEntry {
            display: format_event(&event),
            seq: 99,
            timestamp_micros: 99_000_000,
            source: EventSource::Http,
            severity: EventSeverity::Debug,
            raw: event,
        });
        pane.cursor = 0;

        let selected = pane.selected_event().unwrap();
        assert_eq!(selected.kind(), MailEventKind::HttpRequest);
    }

    #[test]
    fn page_navigation_via_screen() {
        let mut screen = TimelineScreen::new();
        screen.pane.verbosity = VerbosityTier::All;
        let state = TuiSharedState::new(&mcp_agent_mail_core::Config::default());

        // Push 50 events (HTTP 200 = Debug severity).
        for _ in 0..50 {
            let _ = state.push_event(MailEvent::http_request("GET", "/x", 200, 1, "127.0.0.1"));
        }
        screen.pane.ingest(&state);

        // Page down.
        let key_event = Event::Key(ftui::KeyEvent::new(KeyCode::Char('d')));
        screen.update(&key_event, &state);
        assert_eq!(screen.pane.cursor, PAGE_SIZE);

        // Page up.
        let key_event = Event::Key(ftui::KeyEvent::new(KeyCode::Char('u')));
        screen.update(&key_event, &state);
        assert_eq!(screen.pane.cursor, 0);
    }

    #[test]
    fn deep_link_timeline_at_time() {
        let mut screen = TimelineScreen::new();
        screen.pane.verbosity = VerbosityTier::All;
        // Populate with events spanning 0..100 seconds.
        for i in 0..100u64 {
            screen.pane.entries.push(TimelineEntry {
                display: format_event(&make_event(i)),
                seq: i,
                timestamp_micros: i64::try_from(i)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000),
                source: EventSource::Http,
                severity: EventSeverity::Debug,
                raw: make_event(i),
            });
        }
        assert_eq!(screen.pane.cursor, 0);

        // Deep-link to 50 seconds
        let target = DeepLinkTarget::TimelineAtTime(50_000_000);
        let handled = screen.receive_deep_link(&target);
        assert!(handled);
        assert_eq!(screen.pane.cursor, 50);
        assert!(screen.inspector_visible);
    }

    #[test]
    fn deep_link_unrelated_returns_false() {
        let mut screen = TimelineScreen::new();
        let target = DeepLinkTarget::MessageById(42);
        assert!(!screen.receive_deep_link(&target));
    }

    #[test]
    fn default_verbosity_is_standard() {
        let pane = TimelinePane::new();
        assert_eq!(pane.verbosity, VerbosityTier::Standard);
    }

    #[test]
    fn verbosity_filters_by_severity() {
        let mut pane = test_pane();
        // Add entries at different severity levels
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::HealthPulse,
                severity: EventSeverity::Trace,
                timestamp: "00:00:00.000".to_string(),
                icon: '♥',
                summary: "pulse".to_string(),
            },
            seq: 1,
            timestamp_micros: 1_000_000,
            source: EventSource::Database,
            severity: EventSeverity::Trace,
            raw: MailEvent::health_pulse(crate::tui_events::DbStatSnapshot::default()),
        });
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::HttpRequest,
                severity: EventSeverity::Debug,
                timestamp: "00:00:00.001".to_string(),
                icon: '↔',
                summary: "GET / 200".to_string(),
            },
            seq: 2,
            timestamp_micros: 2_000_000,
            source: EventSource::Http,
            severity: EventSeverity::Debug,
            raw: make_event(2),
        });
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::MessageSent,
                severity: EventSeverity::Info,
                timestamp: "00:00:00.002".to_string(),
                icon: '✉',
                summary: "msg".to_string(),
            },
            seq: 3,
            timestamp_micros: 3_000_000,
            source: EventSource::Mail,
            severity: EventSeverity::Info,
            raw: MailEvent::message_sent(1, "A", vec![], "s", "t", "p"),
        });
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::HttpRequest,
                severity: EventSeverity::Error,
                timestamp: "00:00:00.003".to_string(),
                icon: '↔',
                summary: "POST / 500".to_string(),
            },
            seq: 4,
            timestamp_micros: 4_000_000,
            source: EventSource::Http,
            severity: EventSeverity::Error,
            raw: MailEvent::http_request("POST", "/", 500, 10, "127.0.0.1"),
        });

        // All: everything visible
        assert_eq!(pane.verbosity, VerbosityTier::All);
        assert_eq!(pane.filtered_len(), 4);

        // Verbose: Trace hidden
        pane.verbosity = VerbosityTier::Verbose;
        assert_eq!(pane.filtered_len(), 3);

        // Standard: Trace + Debug hidden
        pane.verbosity = VerbosityTier::Standard;
        assert_eq!(pane.filtered_len(), 2);

        // Minimal: only Warn + Error
        pane.verbosity = VerbosityTier::Minimal;
        assert_eq!(pane.filtered_len(), 1);
    }

    #[test]
    fn verbosity_cycles_on_v_key() {
        let mut screen = TimelineScreen::new();
        let state = TuiSharedState::new(&mcp_agent_mail_core::Config::default());
        assert_eq!(screen.pane.verbosity, VerbosityTier::Standard);

        let key = Event::Key(ftui::KeyEvent::new(KeyCode::Char('v')));
        screen.update(&key, &state);
        assert_eq!(screen.pane.verbosity, VerbosityTier::Verbose);

        screen.update(&key, &state);
        assert_eq!(screen.pane.verbosity, VerbosityTier::All);

        screen.update(&key, &state);
        assert_eq!(screen.pane.verbosity, VerbosityTier::Minimal);

        screen.update(&key, &state);
        assert_eq!(screen.pane.verbosity, VerbosityTier::Standard);
    }

    #[test]
    fn clear_filters_resets_verbosity() {
        let mut pane = test_pane();
        pane.verbosity = VerbosityTier::All;
        pane.kind_filter.insert(MailEventKind::HttpRequest);
        pane.source_filter.insert(EventSource::Http);

        pane.clear_filters();
        assert!(pane.kind_filter.is_empty());
        assert!(pane.source_filter.is_empty());
        assert_eq!(pane.verbosity, VerbosityTier::Standard);
    }

    #[test]
    fn verbosity_and_kind_filter_combine() {
        let mut pane = test_pane();
        // Add Info-level message and Debug-level HTTP
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::MessageSent,
                severity: EventSeverity::Info,
                timestamp: "00:00:00.000".to_string(),
                icon: '✉',
                summary: "msg".to_string(),
            },
            seq: 1,
            timestamp_micros: 1_000_000,
            source: EventSource::Mail,
            severity: EventSeverity::Info,
            raw: MailEvent::message_sent(1, "A", vec![], "s", "t", "p"),
        });
        pane.entries.push(TimelineEntry {
            display: EventEntry {
                kind: MailEventKind::HttpRequest,
                severity: EventSeverity::Debug,
                timestamp: "00:00:00.001".to_string(),
                icon: '↔',
                summary: "GET /".to_string(),
            },
            seq: 2,
            timestamp_micros: 2_000_000,
            source: EventSource::Http,
            severity: EventSeverity::Debug,
            raw: make_event(2),
        });

        // All verbosity, no kind filter: both visible
        assert_eq!(pane.filtered_len(), 2);

        // Standard verbosity hides Debug: only Info visible
        pane.verbosity = VerbosityTier::Standard;
        assert_eq!(pane.filtered_len(), 1);

        // Verbose + kind filter for HttpRequest only
        pane.verbosity = VerbosityTier::Verbose;
        pane.kind_filter.insert(MailEventKind::HttpRequest);
        assert_eq!(pane.filtered_len(), 1);
    }
}
