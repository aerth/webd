if [ "x$VERSION" == "x" ]; then
  VERSION=$(git describe --dirty --tags --abbrev=6 --always)
  if [ "x$VERSION" == "x" ]; then
    VERSION=$(cat VERSION)
  fi
  echo "go-generate: found git VERSION=$VERSION"
else
  echo "go-generate: using given VERSION=$VERSION"
fi

if [ "x$VERSION" == "x" ]; then
  echo "couldn't parse version info"
  exit 111;
fi

echo '//go:generate bash scripts/gen_version.bash' > version.go
echo '' >> version.go

echo 'package main' >> version.go
echo '' >> version.go

echo "var Version = \"$VERSION\"" >> version.go
