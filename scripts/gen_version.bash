if [ "x$VERSION" == "x" ]; then
VERSION=`git describe --dirty --tags --abbrev=6 --always`
  echo "go-generate: found VERSION=$VERSION"
else
  echo "go-generate: using VERSION=$VERSION"
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
