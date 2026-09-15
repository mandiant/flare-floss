export type ResultString = {
  string: string;
  offset: number;
  size: number;
  encoding: string;
  tags: string[];
  structure: string;
};

export type ResultLayout = {
  name: string;
  offset: number;
  length: number;
  strings: ResultString[];
  children: ResultLayout[];
};

export type StackString = {
  function: number;
  string: string;
  encoding: string;
  program_counter: number;
  stack_pointer: number;
  original_stack_pointer: number;
  offset: number;
  frame_offset: number;
};

export type TightString = StackString;

export type DecodedString = {
  address: number;
  address_type: string;
  string: string;
  encoding: string;
  decoded_at: number;
  decoding_routine: number;
};

export type StaticString = {
  string: string;
  offset: number;
  encoding: string;
  tags: string[];
  section: string;
  structure: string;
};

export type Runtime = {
  start_date: string;
  total: number;
  vivisect: number;
  find_features: number;
  static_strings: number;
  layout: number;
  tags: number;
  language_strings: number;
  stack_strings: number;
  decoded_strings: number;
  tight_strings: number;
};

export type Functions = {
  discovered: number;
  library: number;
  analyzed_stack_strings: number;
  analyzed_tight_strings: number;
  analyzed_decoded_strings: number;
  decoding_function_scores: Record<string, { score: number; xrefs_to: number }>;
};

export type Analysis = {
  enable_static_strings: boolean;
  enable_stack_strings: boolean;
  enable_tight_strings: boolean;
  enable_decoded_strings: boolean;
  enable_layout: boolean;
  enable_tags: boolean;
  functions: Functions;
};

export type Metadata = {
  file_path: string;
  md5: string;
  sha1: string;
  sha256: string;
  version: string;
  imagebase: number;
  min_length: number;
  runtime: Runtime;
  language: string;
  language_version: string;
  language_selected: string;
};

export type Strings = {
  stack_strings: StackString[];
  tight_strings: TightString[];
  decoded_strings: DecodedString[];
  static_strings: StaticString[];
  language_strings: StaticString[];
  language_strings_missed: StaticString[];
};

export type ResultDocument = {
  metadata: Metadata;
  analysis: Analysis;
  strings: Strings;
  layout: ResultLayout | null;
};
