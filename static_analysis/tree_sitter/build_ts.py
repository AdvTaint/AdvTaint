from tree_sitter import Language, Parser

Language.build_library(
  # Store the library in the `build` directory
  'build/my-languages.so',

  # Include one or more languages
  [
    '/tree_sitter/tree-sitter-c',
    '/tree_sitter/tree-sitter-cpp'
  ]
)