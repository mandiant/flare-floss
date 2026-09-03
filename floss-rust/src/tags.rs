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
                    } else {
                        // TODO: Log invalid regex
                    }
                }
                _ => {
                    // TODO: Log unknown rule type
                }
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
            metadata_by_string.insert(s.string.clone(), s);
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
