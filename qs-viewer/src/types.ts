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

export type Sample = {
  md5: string;
  sha1: string;
  sha256: string;
  path: string;
};

export type Metadata = {
  version: string;
  timestamp: string;
  sample: Sample;
  min_str_len: number;
};

export type ResultDocument = {
  meta: Metadata;
  layout: ResultLayout;
};