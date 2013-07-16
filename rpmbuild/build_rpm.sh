#!/bin/bash

pushd $PWD
mkdir -p rpmbuild/{BUILD,RPMS,S{OURCE,PEC,RPM}S}

BUILD_VERSION=$(ls dist | sed 's/^barbican-\([0-9]\+\.[0-9]\+\.[0-9]\+\)\.tar\.gz/\1/g')
export BUILD_VERSION
echo "Building RPM version $BUILD_VERSION"

cp "dist/barbican-$BUILD_VERSION.tar.gz" rpmbuild/SOURCES
sed -e s/BUILD_VERSION/$BUILD_VERSION/g -i rpmbuild/SPECS/barbican.spec
rpmbuild -ba rpmbuild/SPECS/barbican.spec
popd
