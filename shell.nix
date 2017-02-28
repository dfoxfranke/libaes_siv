{ pkgs ? import <nixpkgs> {} }:
with pkgs;
stdenv.mkDerivation {
  name = "libaes_siv";
  buildInputs = [ cmake asciidoc openssl libxml2 libxslt docbook_xml_dtd_45 docbook_xml_xslt ];
}
