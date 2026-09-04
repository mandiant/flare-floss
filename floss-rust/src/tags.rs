use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, BufRead, BufReader};
use std::path::Path;
use serde::Deserialize;
use flate2::read::GzDecoder;

#[derive(Deserialize, Debug)]
pub struct ExpertRule {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub value: String,
    pub tag: String,
    pub action: String,
    pub note: String,
    pub description: String,
    pub authors: Vec<String>,
    pub references: Vec<String>,
}

pub struct ExpertStringDatabase {
    pub string_rules: HashMap<String, ExpertRule>,
    pub substring_rules: Vec<ExpertRule>,
    pub regex_rules: Vec<(ExpertRule, regex::Regex)>,
}

impl ExpertStringDatabase {
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let decoder = GzDecoder::new(file);
        let reader = BufReader::new(decoder);

        let mut string_rules = HashMap::new();
        let mut substring_rules = Vec::new();
        let mut regex_rules = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let rule: ExpertRule = serde_json::from_str(&line)?;
            match rule.rule_type.as_str() {
                "string" => {
                    string_rules.insert(rule.value.clone(), rule);
                }
                "substring" => {
                    substring_rules.push(rule);
                }
                "regex" => {
                    if let Ok(re) = regex::Regex::new(&rule.value) {
                        regex_rules.push((rule, re));
                    }
                }
                _ => {}
            }
        }

        Ok(ExpertStringDatabase {
            string_rules,
            substring_rules,
            regex_rules,
        })
    }

    pub fn query(&self, s: &str) -> HashSet<String> {
        let mut tags = HashSet::new();

        if let Some(rule) = self.string_rules.get(s) {
            tags.insert(rule.tag.clone());
        }

        for rule in &self.substring_rules {
            if s.contains(&rule.value) {
                tags.insert(rule.tag.clone());
            }
        }

        for (rule, re) in &self.regex_rules {
            if re.is_match(s) {
                tags.insert(rule.tag.clone());
            }
        }

        tags
    }
}

#[derive(Deserialize, Debug)]
pub struct OpenSourceString {
    pub string: String,
    pub library_name: String,
    pub library_version: String,
    pub file_path: Option<String>,
    pub function_name: Option<String>,
    pub line_number: Option<i64>,
}

pub struct OpenSourceStringDatabase {
    pub metadata_by_string: HashMap<String, OpenSourceString>,
}

impl OpenSourceStringDatabase {
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let decoder = GzDecoder::new(file);
        let reader = BufReader::new(decoder);

        let mut metadata_by_string = HashMap::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let s: OpenSourceString = serde_json::from_str(&line)?;
            metadata_by_string.insert(s.string.to_string(), s);
        }

        Ok(OpenSourceStringDatabase { metadata_by_string })
    }

    pub fn query(&self, s: &str) -> Option<String> {
        self.metadata_by_string.get(s).map(|meta| format!("#{}", meta.library_name))
    }
}

pub struct StringHashDatabase {
    pub string_hashes: HashSet<[u8; 8]>,
}

impl StringHashDatabase {
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let mut string_hashes = HashSet::new();
        for chunk in buf.chunks_exact(8) {
            let mut hash = [0u8; 8];
            hash.copy_from_slice(chunk);
            string_hashes.insert(hash);
        }

        Ok(StringHashDatabase { string_hashes })
    }

    pub fn contains(&self, s: &str) -> bool {
        let digest = md5::compute(s.as_bytes());
        let hash: [u8; 8] = digest.0[..8].try_into().unwrap();
        self.string_hashes.contains(&hash)
    }
}

use std::ops::Range;
use crate::results::StaticString;
use crate::results::StringEncoding;

pub fn ranges_overlap(r1: &Range<usize>, r2: &Range<usize>) -> bool {
    r1.start < r2.end && r2.start < r1.end
}

pub fn tag_strings(
    strings: &[crate::strings::StaticString],
    code_ranges: &[Range<usize>],
    reloc_ranges: &[Range<usize>],
    layout: &crate::layout::Layout,
    expert_db: Option<&ExpertStringDatabase>,
    os_db: Option<&OpenSourceStringDatabase>,
    gp_db: Option<&StringHashDatabase>,
) -> Vec<StaticString> {
    let mut tagged_strings = Vec::new();

    for s in strings {
        let mut tags = HashSet::new();
        let s_range = s.offset..(s.offset + s.length);

        // 1. Layout derived tags
        // #code
        if code_ranges.iter().any(|r| ranges_overlap(&s_range, r)) {
            tags.insert("#code".to_string());
        }

        // #reloc
        if reloc_ranges.iter().any(|r| ranges_overlap(&s_range, r)) {
            tags.insert("#reloc".to_string());
        }


        // 2. Database derived tags
        if let Some(db) = expert_db {
            let expert_tags = db.query(&s.string);
            for t in expert_tags {
                tags.insert(t);
            }
        }

        if let Some(db) = os_db {
            if let Some(t) = db.query(&s.string) {
                tags.insert(t);
            }
        }

        if let Some(db) = gp_db {
            if db.contains(&s.string) {
                tags.insert("#common".to_string());
            }
        }

        // Convert HashSet into a sorted Vec for deterministic JSON output
        let mut tags_vec: Vec<String> = tags.into_iter().collect();
        tags_vec.sort();

        let encoding = match s.encoding {
            crate::strings::StringEncoding::ASCII => StringEncoding::Ascii,
            crate::strings::StringEncoding::UTF16LE => StringEncoding::Utf16Le,
        };

        tagged_strings.push(StaticString {
            offset: s.offset,
            string: s.string.to_string(),
            encoding,
            tags: tags_vec,
            section: find_section(&s_range, layout),
            structure: String::new(), // Not implemented yet
        });
    }

    tagged_strings
}

fn find_section(s_range: &Range<usize>, layout: &crate::layout::Layout) -> String {
    // DFS to find the deepest matching child Node. (like sections in PE)
    for child in &layout.children {
        let child_range = child.offset..(child.offset + child.length);
        if ranges_overlap(s_range, &child_range) {
            return child.name.clone();
        }
    }
    String::new()
}

impl ExpertStringDatabase {
    pub fn from_uncompressed_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut string_rules = HashMap::new();
        let mut substring_rules = Vec::new();
        let mut regex_rules = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let rule: ExpertRule = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => continue,
            };
            match rule.rule_type.as_str() {
                "string" => {
                    string_rules.insert(rule.value.clone(), rule);
                }
                "substring" => {
                    substring_rules.push(rule);
                }
                "regex" => {
                    if let Ok(re) = regex::Regex::new(&rule.value) {
                        regex_rules.push((rule, re));
                    }
                }
                _ => {}
            }
        }

        Ok(ExpertStringDatabase {
            string_rules,
            substring_rules,
            regex_rules,
        })
    }
}
