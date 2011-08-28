all:
	rm -rf ~/.cabal/lib/nacl-0.1/
	rm -rf dist
	cabal configure --user -v
	cabal build -v
	cabal haddock --hyperlink-source -v
	cabal install -v
