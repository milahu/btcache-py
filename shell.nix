{
  pkgs ? import <nixpkgs> { }
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    (python3.withPackages (pp: with pp; [
      libtorrent-rasterbar
      requests
      pyyaml
      torf
    ]))
  ];
}
