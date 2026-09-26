//! The screen buffer: cells, fields, cursor and geometry.
//!
//! A 3270 screen is a flat array of positions addressed 0..rows*cols, and
//! addresses wrap round at the end. Some positions hold a **field attribute**
//! rather than a character: that byte occupies a visible cell, renders as a
//! blank, and governs every position after it up to the next attribute. This
//! is the single most common thing to get wrong when writing an emulator,
//! because it makes a field's first data column one greater than the column
//! its attribute sits in.

use crate::ds::attr::{Extended, FieldAttr};
use crate::ebcdic::CodePage;

/// A terminal model, which fixes the alternate screen size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Model {
    /// 24 rows by 80 columns: the alternate size equals the primary size.
    #[default]
    Model2,
    /// 32 by 80.
    Model3,
    /// 43 by 80.
    Model4,
    /// 27 by 132.
    Model5,
}

impl Model {
    /// Every model shares this primary screen size.
    pub const PRIMARY: (u16, u16) = (24, 80);

    pub const fn number(self) -> u8 {
        match self {
            Model::Model2 => 2,
            Model::Model3 => 3,
            Model::Model4 => 4,
            Model::Model5 => 5,
        }
    }

    pub const fn from_number(n: u8) -> Option<Model> {
        match n {
            2 => Some(Model::Model2),
            3 => Some(Model::Model3),
            4 => Some(Model::Model4),
            5 => Some(Model::Model5),
            _ => None,
        }
    }

    /// `(rows, cols)` of the alternate screen, which an Erase/Write/Alternate
    /// selects.
    pub const fn alternate(self) -> (u16, u16) {
        match self {
            Model::Model2 => (24, 80),
            Model::Model3 => (32, 80),
            Model::Model4 => (43, 80),
            Model::Model5 => (27, 132),
        }
    }

    /// Cells in the alternate screen.
    pub const fn alternate_cells(self) -> u16 {
        let (r, c) = self.alternate();
        r * c
    }
}

impl core::fmt::Display for Model {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (r, c) = self.alternate();
        write!(f, "model {} ({r}x{c})", self.number())
    }
}

/// One screen position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cell {
    /// The EBCDIC byte here. `0x00` is an unwritten position, which renders
    /// blank but is *not* a space: it is dropped from inbound field data.
    pub byte: u8,
    /// `Some` when this position holds a field attribute rather than data.
    pub field: Option<FieldAttr>,
    /// Character-level or field-level extended attributes.
    pub extended: Extended,
    /// Set when the byte came after a Graphic Escape, so it is from the
    /// alternate character set rather than the code page.
    pub graphic_escape: bool,
}

impl Cell {
    /// True when this position holds a field attribute.
    pub const fn is_field_start(&self) -> bool {
        self.field.is_some()
    }

    /// True when nothing has been written here.
    pub const fn is_empty(&self) -> bool {
        self.byte == 0x00 && self.field.is_none()
    }
}

/// A field: its attribute position, its data range, and its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Address of the attribute byte itself.
    pub attr_addr: u16,
    /// Address of the first data position, one past the attribute.
    pub start: u16,
    /// Number of data positions, excluding the attribute.
    pub len: u16,
    pub attr: FieldAttr,
}

/// The screen buffer.
#[derive(Debug, Clone)]
pub struct Screen {
    model: Model,
    rows: u16,
    cols: u16,
    buf: Vec<Cell>,
    cursor: u16,
    code_page: CodePage,
    /// Set when the host rang the bell; the caller clears it.
    pub alarm: bool,
}

impl Screen {
    /// A screen at the model's **alternate** size, which is what a host
    /// selects with Erase/Write/Alternate.
    pub fn new(model: Model) -> Self {
        let (rows, cols) = model.alternate();
        Screen {
            model,
            rows,
            cols,
            buf: vec![Cell::default(); usize::from(rows) * usize::from(cols)],
            cursor: 0,
            code_page: crate::ebcdic::DEFAULT,
            alarm: false,
        }
    }

    /// A screen at the primary 24x80 size for the given model.
    pub fn primary(model: Model) -> Self {
        let mut s = Screen::new(model);
        s.select_primary();
        s
    }

    pub fn model(&self) -> Model {
        self.model
    }

    pub fn rows(&self) -> u16 {
        self.rows
    }

    pub fn cols(&self) -> u16 {
        self.cols
    }

    /// Total addressable positions.
    pub fn size(&self) -> u16 {
        self.rows * self.cols
    }

    pub fn code_page(&self) -> CodePage {
        self.code_page
    }

    pub fn set_code_page(&mut self, code_page: CodePage) {
        self.code_page = code_page;
    }

    /// True when this screen is currently at the alternate size.
    pub fn is_alternate(&self) -> bool {
        (self.rows, self.cols) == self.model.alternate()
    }

    /// Switch to the primary 24x80 size and erase. Erase/Write does this.
    pub fn select_primary(&mut self) {
        self.resize(Model::PRIMARY.0, Model::PRIMARY.1);
    }

    /// Switch to the model's alternate size and erase.
    /// Erase/Write/Alternate does this.
    pub fn select_alternate(&mut self) {
        let (r, c) = self.model.alternate();
        self.resize(r, c);
    }

    /// Set an explicit geometry, as a BIND image may dictate.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.rows = rows.max(1);
        self.cols = cols.max(1);
        self.buf.clear();
        self.buf.resize(
            usize::from(self.rows) * usize::from(self.cols),
            Cell::default(),
        );
        self.cursor = 0;
    }

    /// Erase every position and home the cursor.
    pub fn clear(&mut self) {
        for cell in &mut self.buf {
            *cell = Cell::default();
        }
        self.cursor = 0;
    }

    // ------------------------------------------------------------ geometry --

    /// Address of a 1-based row and column.
    pub fn addr_of(&self, row: u16, col: u16) -> u16 {
        let row = row.saturating_sub(1).min(self.rows - 1);
        let col = col.saturating_sub(1).min(self.cols - 1);
        row * self.cols + col
    }

    /// The 1-based row and column of an address.
    pub fn row_col(&self, addr: u16) -> (u16, u16) {
        let addr = addr % self.size();
        (addr / self.cols + 1, addr % self.cols + 1)
    }

    /// The next address, wrapping at the end of the buffer.
    pub fn inc(&self, addr: u16) -> u16 {
        (addr + 1) % self.size()
    }

    /// The previous address, wrapping at the start of the buffer.
    pub fn dec(&self, addr: u16) -> u16 {
        (addr + self.size() - 1) % self.size()
    }

    // ---------------------------------------------------------------- cells --

    pub fn cell(&self, addr: u16) -> &Cell {
        &self.buf[usize::from(addr % self.size())]
    }

    pub fn cell_mut(&mut self, addr: u16) -> &mut Cell {
        let i = usize::from(addr % self.size());
        &mut self.buf[i]
    }

    pub fn cells(&self) -> &[Cell] {
        &self.buf
    }

    pub fn cursor(&self) -> u16 {
        self.cursor
    }

    pub fn set_cursor(&mut self, addr: u16) {
        self.cursor = addr % self.size();
    }

    pub fn cursor_row_col(&self) -> (u16, u16) {
        self.row_col(self.cursor)
    }

    // --------------------------------------------------------------- fields --

    /// True when the screen contains at least one field attribute.
    ///
    /// An unformatted screen has none, and the host reads it differently.
    pub fn is_formatted(&self) -> bool {
        self.buf.iter().any(Cell::is_field_start)
    }

    /// Address of the field attribute governing `addr`, searching backwards
    /// and wrapping. `None` on an unformatted screen.
    pub fn field_attr_addr(&self, addr: u16) -> Option<u16> {
        let size = self.size();
        let mut a = addr % size;
        for _ in 0..size {
            if self.cell(a).is_field_start() {
                return Some(a);
            }
            a = self.dec(a);
        }
        None
    }

    /// The field attribute governing `addr`.
    pub fn field_attr(&self, addr: u16) -> Option<FieldAttr> {
        self.field_attr_addr(addr).and_then(|a| self.cell(a).field)
    }

    /// True when the operator may type at `addr`.
    ///
    /// An unformatted screen is entirely writable; a formatted one is writable
    /// only inside an unprotected field, and never on the attribute byte.
    pub fn is_writable(&self, addr: u16) -> bool {
        if self.cell(addr).is_field_start() {
            return false;
        }
        match self.field_attr(addr) {
            Some(attr) => attr.is_input(),
            None => true,
        }
    }

    /// Every field on the screen, in address order from the first attribute.
    pub fn fields(&self) -> Vec<Field> {
        let size = self.size();
        let mut starts: Vec<u16> = (0..size)
            .filter(|&a| self.cell(a).is_field_start())
            .collect();
        if starts.is_empty() {
            return Vec::new();
        }
        starts.sort_unstable();
        let mut out = Vec::with_capacity(starts.len());
        for (i, &attr_addr) in starts.iter().enumerate() {
            let next = starts[(i + 1) % starts.len()];
            // Data runs from just after the attribute up to the next one,
            // wrapping round the end of the buffer.
            let len = (next + size - attr_addr - 1) % size;
            out.push(Field {
                attr_addr,
                start: self.inc(attr_addr),
                len,
                attr: self
                    .cell(attr_addr)
                    .field
                    .expect("filtered on is_field_start"),
            });
        }
        out
    }

    /// The raw EBCDIC bytes of a field's data, nulls included.
    pub fn field_bytes(&self, field: &Field) -> Vec<u8> {
        (0..field.len)
            .map(|i| self.cell(field.start.wrapping_add(i)).byte)
            .collect()
    }

    /// A field's data as text, with nulls rendered as spaces and trailing
    /// blanks trimmed.
    ///
    /// Unlike [`Screen::row_text`] this returns the buffer's real content even
    /// for a non-display field, which is what automation wants: the client
    /// typed that content, so it is not a secret being revealed.
    pub fn field_text(&self, field: &Field) -> String {
        let bytes = self.field_bytes(field);
        let text = self.decode(&bytes);
        text.trim_end().to_string()
    }

    /// Set or clear the modified-data-tag on the field governing `addr`.
    pub fn set_modified(&mut self, addr: u16, modified: bool) {
        if let Some(a) = self.field_attr_addr(addr) {
            if let Some(attr) = self.cell_mut(a).field.as_mut() {
                attr.set_modified(modified);
            }
        }
    }

    /// Clear the modified-data-tag on every field, as a WCC can ask.
    pub fn reset_all_modified(&mut self) {
        for cell in &mut self.buf {
            if let Some(attr) = cell.field.as_mut() {
                attr.set_modified(false);
            }
        }
    }

    // ----------------------------------------------------------------- text --

    /// Decode EBCDIC bytes with this screen's code page, nulls as spaces.
    pub fn decode(&self, bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|&b| {
                if b == 0x00 {
                    ' '
                } else {
                    self.code_page.decode_byte(b).unwrap_or(' ')
                }
            })
            .collect()
    }

    /// One row as text, 1-based.
    ///
    /// Renders what an operator would see: attribute positions are blank, and
    /// so is the content of a non-display (password) field. This matches
    /// x3270's `Ascii()` output, so the two can be compared directly. Use
    /// [`Screen::field_bytes`] to read a hidden field's actual content.
    pub fn row_text(&self, row: u16) -> String {
        let start = self.addr_of(row, 1);
        // The attribute in force at the start of the row may have been set on
        // an earlier row, so seed it by searching backwards.
        let mut hidden = self
            .field_attr(start)
            .map(|a| a.is_hidden())
            .unwrap_or(false);
        let mut out = String::with_capacity(usize::from(self.cols));
        for i in 0..self.cols {
            let cell = self.cell(start + i);
            if let Some(attr) = cell.field {
                // The attribute byte itself is blank, and it changes what
                // follows.
                hidden = attr.is_hidden();
                out.push(' ');
            } else if hidden || cell.byte == 0x00 {
                out.push(' ');
            } else {
                out.push(self.code_page.decode_byte(cell.byte).unwrap_or(' '));
            }
        }
        out
    }

    /// The whole screen as text, one line per row.
    pub fn text(&self) -> String {
        (1..=self.rows)
            .map(|r| self.row_text(r))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Find text on the screen, returning the 1-based row and column of the
    /// first match. Rows are searched in order and matches do not span rows.
    pub fn find(&self, needle: &str) -> Option<(u16, u16)> {
        if needle.is_empty() {
            return None;
        }
        for row in 1..=self.rows {
            if let Some(byte_idx) = self.row_text(row).find(needle) {
                // row_text is one char per column, so a char index is a column.
                let col = self.row_text(row)[..byte_idx].chars().count() as u16 + 1;
                return Some((row, col));
            }
        }
        None
    }

    /// Text at a 1-based position, `len` columns wide, clipped to the row.
    pub fn text_at(&self, row: u16, col: u16, len: u16) -> String {
        let row_text = self.row_text(row);
        let chars: Vec<char> = row_text.chars().collect();
        let start = usize::from(col.saturating_sub(1)).min(chars.len());
        let end = (start + usize::from(len)).min(chars.len());
        chars[start..end].iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ds::attr::Intensity;

    fn screen_with_fields() -> Screen {
        // Attribute at (1,1); data "AB" at (1,2)-(1,3); second field at (1,10).
        let mut s = Screen::primary(Model::Model2);
        s.cell_mut(0).field = Some(FieldAttr::new(false, false, Intensity::Normal, false));
        s.cell_mut(1).byte = 0xC1; // A
        s.cell_mut(2).byte = 0xC2; // B
        s.cell_mut(9).field = Some(FieldAttr::new(true, false, Intensity::Normal, false));
        s.cell_mut(10).byte = 0xC3; // C
        s
    }

    #[test]
    fn model_geometry_matches_the_standard() {
        assert_eq!(Model::Model2.alternate(), (24, 80));
        assert_eq!(Model::Model3.alternate(), (32, 80));
        assert_eq!(Model::Model4.alternate(), (43, 80));
        assert_eq!(Model::Model5.alternate(), (27, 132));
        assert_eq!(Model::Model4.alternate_cells(), 3440);
        assert_eq!(Model::Model5.alternate_cells(), 3564);
        assert_eq!(Model::from_number(4), Some(Model::Model4));
        assert_eq!(Model::from_number(6), None);
    }

    #[test]
    fn primary_and_alternate_sizes_switch() {
        let mut s = Screen::new(Model::Model4);
        assert_eq!((s.rows(), s.cols()), (43, 80));
        assert!(s.is_alternate());
        s.select_primary();
        assert_eq!((s.rows(), s.cols()), (24, 80));
        assert!(!s.is_alternate());
        s.select_alternate();
        assert_eq!((s.rows(), s.cols()), (43, 80));

        // On a model 2 the two sizes coincide.
        let m2 = Screen::primary(Model::Model2);
        assert!(m2.is_alternate());
    }

    #[test]
    fn addresses_and_row_columns_agree() {
        let s = Screen::primary(Model::Model2);
        assert_eq!(s.addr_of(1, 1), 0);
        assert_eq!(s.row_col(0), (1, 1));
        assert_eq!(s.addr_of(1, 80), 79);
        assert_eq!(s.addr_of(2, 1), 80);
        assert_eq!(s.row_col(80), (2, 1));
        assert_eq!(s.addr_of(24, 80), 1919);
        assert_eq!(s.row_col(1919), (24, 80));
        for addr in 0..s.size() {
            let (r, c) = s.row_col(addr);
            assert_eq!(s.addr_of(r, c), addr);
        }
    }

    #[test]
    fn addresses_wrap_at_the_end_of_the_buffer() {
        let s = Screen::primary(Model::Model2);
        assert_eq!(s.inc(1919), 0, "the last cell wraps to the origin");
        assert_eq!(s.dec(0), 1919);
        assert_eq!(s.row_col(1920), (1, 1), "an out-of-range address wraps");
    }

    #[test]
    fn a_field_starts_one_column_after_its_attribute() {
        let s = screen_with_fields();
        let fields = s.fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].attr_addr, 0);
        assert_eq!(fields[0].start, 1, "data begins after the attribute byte");
        assert_eq!(fields[0].len, 8, "runs up to the next attribute at 9");
        assert_eq!(s.field_text(&fields[0]), "AB");
    }

    #[test]
    fn the_last_field_wraps_round_to_the_first() {
        let s = screen_with_fields();
        let fields = s.fields();
        // Second field runs from 10 to the end of the buffer and round to 0.
        assert_eq!(fields[1].attr_addr, 9);
        assert_eq!(fields[1].start, 10);
        assert_eq!(fields[1].len, 1920 - 10);
    }

    #[test]
    fn writability_follows_the_governing_attribute() {
        let s = screen_with_fields();
        assert!(!s.is_writable(0), "never writable on the attribute byte");
        assert!(s.is_writable(1), "inside the unprotected field");
        assert!(s.is_writable(8), "still inside it");
        assert!(!s.is_writable(9), "attribute byte of the protected field");
        assert!(!s.is_writable(10), "inside the protected field");
    }

    #[test]
    fn an_unformatted_screen_is_entirely_writable() {
        let s = Screen::primary(Model::Model2);
        assert!(!s.is_formatted());
        assert!(s.field_attr(0).is_none());
        assert!(s.is_writable(0) && s.is_writable(1919));
        assert!(s.fields().is_empty());
    }

    #[test]
    fn modified_tags_set_and_reset() {
        let mut s = screen_with_fields();
        assert!(!s.fields()[0].attr.is_modified());
        s.set_modified(5, true);
        assert!(
            s.fields()[0].attr.is_modified(),
            "setting via any address in the field"
        );
        assert!(!s.fields()[1].attr.is_modified());
        s.reset_all_modified();
        assert!(s.fields().iter().all(|f| !f.attr.is_modified()));
    }

    #[test]
    fn text_rendering_blanks_attributes_and_nulls() {
        let s = screen_with_fields();
        let row = s.row_text(1);
        assert_eq!(row.chars().count(), 80);
        // Attribute at column 1 renders blank, data starts at column 2.
        assert!(row.starts_with(" AB"));
        assert_eq!(s.text_at(1, 2, 2), "AB");
        assert_eq!(s.text().lines().count(), 24);
    }

    #[test]
    fn find_locates_text_with_one_based_coordinates() {
        let s = screen_with_fields();
        assert_eq!(s.find("AB"), Some((1, 2)));
        assert_eq!(s.find("C"), Some((1, 11)));
        assert_eq!(s.find("ZZ"), None);
        assert_eq!(s.find(""), None);
    }

    #[test]
    fn non_display_fields_render_blank_but_keep_their_content() {
        let mut s = Screen::primary(Model::Model2);
        s.cell_mut(0).field = Some(FieldAttr::new(false, false, Intensity::Hidden, false));
        s.cell_mut(1).byte = 0xD7; // P
        s.cell_mut(2).byte = 0xE6; // W
        s.cell_mut(9).field = Some(FieldAttr::new(true, false, Intensity::Normal, false));
        s.cell_mut(10).byte = 0xC1; // A

        // Rendered: the password is blanked, later fields are not.
        let row = s.row_text(1);
        assert_eq!(&row[..3], "   ", "a non-display field renders blank");
        assert_eq!(row.chars().nth(10), Some('A'), "the next field still shows");

        // The buffer still holds it, for automation to read back.
        let pw = &s.fields()[0];
        assert!(pw.attr.is_hidden());
        assert_eq!(s.field_text(pw), "PW");
    }

    #[test]
    fn a_field_hidden_on_an_earlier_row_still_blanks_this_one() {
        // The governing attribute is seeded by searching backwards, so a field
        // spanning a row boundary stays hidden.
        let mut s = Screen::primary(Model::Model2);
        s.cell_mut(70).field = Some(FieldAttr::new(false, false, Intensity::Hidden, false));
        s.cell_mut(85).byte = 0xC1; // A, on row 2, inside the hidden field
        assert_eq!(
            s.row_text(2).trim(),
            "",
            "row 2 inherits the hidden attribute"
        );
    }

    #[test]
    fn clear_empties_the_buffer_and_homes_the_cursor() {
        let mut s = screen_with_fields();
        s.set_cursor(500);
        s.clear();
        assert_eq!(s.cursor(), 0);
        assert!(!s.is_formatted());
        assert!(s.cells().iter().all(Cell::is_empty));
    }
}
