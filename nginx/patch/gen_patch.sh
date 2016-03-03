# /bin/sh

###########################################################
VERSION=1.4.1
NAME=nginx

echo "begin generate ${NAME}-${VERSION}.patch ..."
tar -zxf ${NAME}-${VERSION}.tar.gz
rm -rf `find ${NAME}-${VERSION} -name .svn`
tar -zcf ${NAME}-${VERSION}.tar.gz ${NAME}-${VERSION}

cp -r ${NAME}-${VERSION} ${NAME}-${VERSION}-new
cp -r ./${NAME}/* ./${NAME}-${VERSION}-new
rm -rf `find ${NAME}-${VERSION}-new -name .svn`

diff -Naur ${NAME}-${VERSION} ${NAME}-${VERSION}-new > ${NAME}-${VERSION}.patch
rm -rf ${NAME}-${VERSION}
rm -rf ${NAME}-${VERSION}-new
echo "finish generate ${NAME}-${VERSION}.patch"
###########################################################
