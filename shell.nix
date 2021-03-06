{ nixpkgs ? import <nixpkgs> {}, compiler ? "default" }:

let

  inherit (nixpkgs) pkgs;

  f = { mkDerivation, acid-state, aeson, authenticate, base
      , base64-bytestring, boomerang, bytestring, containers
      , data-default, email-validate, filepath, happstack-hsp
      , happstack-jmacro, happstack-server, hsp, hsx-jmacro, hsx2hs
      , http-conduit, http-types, ixset-typed, jmacro, jwt, lens
      , mime-mail, mtl, pwstore-purehaskell, random, safecopy
      , shakespeare, stdenv, text, time, unordered-containers, userid
      , web-routes, web-routes-boomerang, web-routes-happstack
      , web-routes-hsp, web-routes-th, cabal-install
      }:
      mkDerivation {
        pname = "happstack-authenticate";
        version = "2.3.0";
        src = ./.;
        libraryHaskellDepends = [
          acid-state aeson authenticate base base64-bytestring boomerang
          bytestring containers data-default email-validate filepath
          happstack-hsp happstack-jmacro happstack-server hsp hsx-jmacro
          hsx2hs http-conduit http-types ixset-typed jmacro jwt lens
          mime-mail mtl pwstore-purehaskell random safecopy shakespeare text
          time unordered-containers userid web-routes web-routes-boomerang
          web-routes-happstack web-routes-hsp web-routes-th cabal-install
        ];
        buildTools = [];
        homepage = "http://www.happstack.com/";
        description = "Happstack Authentication Library";
        license = stdenv.lib.licenses.bsd3;
      };

  haskellPackages = if compiler == "default"
                       then pkgs.haskellPackages
                       else pkgs.haskell.packages.${compiler};

  drv = haskellPackages.callPackage f {};

in

  if pkgs.lib.inNixShell then drv.env else drv
