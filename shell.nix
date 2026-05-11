{
  pkgs ? import <nixpkgs> { }
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    (python3.withPackages (pp: with pp; [
      (
      if true then libtorrent-rasterbar else
      # else: use a patched libtorrent with th.forget_pieces
      (toPythonModule ((pkgs.libtorrent-rasterbar.override {
        python3 = python;
      }).overrideAttrs (oldAttrs: {
        src =
        # if true then /home/user/src/libtorrent else
        pkgs.fetchFromGitHub {
          owner = "milahu";
          repo = "libtorrent";
          # https://github.com/milahu/libtorrent/tree/add-forget_pieces-force_recheck_pieces
          rev = "1ce9da8f7aca1d0e760024f5167ef113074bac02";
          hash = "sha256-u2FfB0jbGIS/9NunmLYsIY8/YKo7pvqopBVzyZ0J/+o=";
          fetchSubmodules = true;
        };
      }))).python
      )
      requests
      ruamel-yaml # ruamel.yaml
      torf
    ]))
  ];
}
