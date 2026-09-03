use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StringEncoding {
    Ascii,
    #[serde(rename = "UTF-16LE")]
    Utf16Le,
    #[serde(rename = "UTF-8")]
    Utf8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResultString {
    pub string: String,
    pub offset: usize,
    pub size: usize,
    pub encoding: String,
    pub tags: Vec<String>,
    pub structure: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResultLayout {
    pub name: String,
    pub offset: usize,
    pub length: usize,
    pub strings: Vec<ResultString>,
    pub children: Vec<ResultLayout>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Runtime {
    pub start_date: String, // Or use DateTime if we add chrono
    pub total: f64,
    pub vivisect: f64,
    pub find_features: f64,
    pub static_strings: f64,
    pub layout: f64,
    pub tags: f64,
    pub language_strings: f64,
    pub stack_strings: f64,
    pub decoded_strings: f64,
    pub tight_strings: f64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Functions {
    pub discovered: usize,
    pub library: usize,
    pub analyzed_stack_strings: usize,
    pub analyzed_tight_strings: usize,
    pub analyzed_decoded_strings: usize,
    pub decoding_function_scores: std::collections::HashMap<usize, std::collections::HashMap<String, f64>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Analysis {
    pub enable_static_strings: bool,
    pub enable_stack_strings: bool,
    pub enable_tight_strings: bool,
    pub enable_decoded_strings: bool,
    pub enable_language_strings: bool,
    pub enable_layout: bool,
    pub enable_tags: bool,
    pub functions: Functions,
}

impl Default for Analysis {
    fn default() -> Self {
        Analysis {
            enable_static_strings: true,
            enable_stack_strings: false,
            enable_tight_strings: false,
            enable_decoded_strings: false,
            enable_language_strings: false,
            enable_layout: true,
            enable_tags: true,
            functions: Functions::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Metadata {
    pub file_path: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub version: String,
    pub imagebase: usize,
    pub min_length: usize,
    pub runtime: Runtime,
    pub language: String,
    pub language_version: String,
    pub language_selected: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StaticString {
    pub string: String,
    pub offset: usize,
    pub encoding: StringEncoding,
    pub tags: Vec<String>,
    pub section: String,
    pub structure: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Strings {
    pub stack_strings: Vec<String>, // simplified for now
    pub tight_strings: Vec<String>,
    pub decoded_strings: Vec<String>,
    pub static_strings: Vec<StaticString>,
    pub language_strings: Vec<String>,
    pub language_strings_missed: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResultDocument {
    pub metadata: Metadata,
    pub analysis: Analysis,
    pub strings: Strings,
    pub layout: Option<ResultLayout>,
}

impl ResultLayout {
    pub fn from_layout(
        layout: &crate::layout::Layout,
        tagged_strings: &[StaticString],
    ) -> ResultLayout {
        let mut strings = Vec::new();
        // Simple O(N^2) or just filter for now
        let layout_end = layout.offset + layout.length;
        
        for s in tagged_strings {
            if s.offset >= layout.offset && (s.offset + s.string.len()) <= layout_end {
                // If it belongs to a child, don't include it in this?
                // Wait, python floss includes it ONLY in the tightest bounds. 
                // We'll mimic this soon, just a start.
            }
        }
        
        let children = layout.children.iter().map(|c| ResultLayout::from_layout(c, tagged_strings)).collect();
        ResultLayout {
            name: layout.name.clone(),
            offset: layout.offset,
            length: layout.length,
            strings,
            children,
        }
    }
}
