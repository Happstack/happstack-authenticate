with (import <nixpkgs> {}).pkgs;
let pkg = haskellngPackages.callPackage
            ({ mkDerivation, acid-state, aeson, authenticate, base
             , base64-bytestring, boomerang, bytestring, containers
             , data-default, filepath, happstack-hsp, happstack-jmacro
             , happstack-server, hsp, hsx-jmacro, hsx2hs, http-conduit
             , http-types, ixset-typed, jmacro, jwt, lens, mime-mail, mtl
             , pwstore-purehaskell, random, safecopy, shakespeare, stdenv, text
             , time, unordered-containers, web-routes, web-routes-boomerang
             , web-routes-happstack, web-routes-hsp, web-routes-th
             }:
             mkDerivation {
               pname = "happstack-authenticate";
               version = "2.1.3";
               src = ./.;
               buildDepends = [
                 acid-state aeson authenticate base base64-bytestring boomerang
                 bytestring containers data-default filepath happstack-hsp
                 happstack-jmacro happstack-server hsp hsx-jmacro hsx2hs
                 http-conduit http-types ixset-typed jmacro jwt lens mime-mail mtl
                 pwstore-purehaskell random safecopy shakespeare text time
                 unordered-containers web-routes web-routes-boomerang
                 web-routes-happstack web-routes-hsp web-routes-th
               ];
               homepage = "http://www.happstack.com/";
               description = "Happstack Authentication Library";
               license = stdenv.lib.licenses.bsd3;
             }) {};
in
  pkg.env
