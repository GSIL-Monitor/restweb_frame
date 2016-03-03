nginx_navi rpm包（session服务）及相关依赖包制作

#####################################################################################
相关spec文件有：
libnaviutil.spec
libsession.spec
nginx_navi.spec
#####################################################################################

#####################################################################################
相关src包有：
libnaviutil.tar.gz
libsession.tar.gz
nginx_navi/SOURCES/*
#####################################################################################

#####################################################################################
相关依赖关系为：
nginx_navi Requires libnaviutil（以及nginx-1.0.12需要依赖的库）
    libnaviutil Requires jansson libredisproxy
        libsession Requires libnaviutil

制作过程示例：
1 制作libnaviutil rpm包
svn co http://gforge.1verge.net/svn/libnaviutil/trunk ./libcnavi-0.2.0
tar  -zcvf libcnavi-0.2.0.tar.gz libcnavi-0.2.0
cp libcnavi-0.2.0/rpmbuild/libcnavi-0.2.0.spec /opt/dqiu/rpmbuild/SPECS
cp libcnavi-0.2.0.tar.gz /opt/dqiu/rpmbuild/SOURCES/
cd /opt/dqiu/rpmbuild/SPECS
rpmbuild -ba libcnavi-0.2.0.spec
cd /opt/dqiu/rpmbuild/RPMS/x86_64/
rpm -Uvh libcnavi-0.2.0-1.el5.x86_64.rpm libcnavi-devel-0.2.0-1.el5.x86_64.rpm
rpm -ivh libcnavi-driver-0.2.0-1.el5.x86_64.rpm libcnavi-driver-devel-0.2.0-1.el5.x86_64.rpm

2 制作libsession rpm包
svn co http://gforge.1verge.net/svn/libnavisession/trunk libsession-0.1.0
tar -zcvf libsession-0.1.0.tar.gz libsession-0.1.0
cp libsession-0.1.0/rpmbuild/libsession-0.1.0.spec /opt/dqiu/rpmbuild/SPECS/
cp libsession-0.1.0.tar.gz /opt/dqiu/rpmbuild/SOURCES/
cd /opt/dqiu/rpmbuild/SPECS
rpmbuild -ba libsession-0.1.0.spec
cd /opt/dqiu/rpmbuild/RPMS/x86_64/
rpm -Uvh libsession-0.1.0-3.el5.x86_64.rpm libsession-devel-0.1.0-3.el5.x86_64.rpm

3 制作nginx_navi rpm包
svn co http://gforge.1verge.net/svn/nginx_navi/trunk ./nginx_navi-1.4.1
cp ./nginx_navi-1.4.1/SPECS/nginx_navi-1.4.1.spec /opt/dqiu/rpmbuild/SPECS/
cp ./nginx_navi-1.4.1/SOURCES/* /opt/dqiu/rpmbuild/SOURCES/
svn co http://gforge.1verge.net/svn/nginx_navi_mod/trunk ./nginx_navi_mod
tar -zcvf nginx_navi_mod.tar.gz nginx_navi_mod
cp nginx_navi_mod.tar.gz /opt/dqiu/rpmbuild/SOURCES/
cd /opt/dqiu/rpmbuild/SPECS
rpmbuild -ba nginx_navi-1.4.1.spec
rpm -Uvh  nginx_navi-1.4.1-1.el5.x86_64.rpm
#####################################################################################

#####################################################################################
1 制作nbatch rpm包
svn co http://gforge.1verge.net/svn/nbatch/trunk libnbatch-0.2.0
tar -zcvf libnbatch-0.2.0.tar.gz libnbatch-0.2.0
cp libnbatch-0.2.0/libnbatch-0.2.0.spec /opt/dqiu/rpmbuild/SPECS/
cp libnbatch-0.2.0.tar.gz /opt/dqiu/rpmbuild/SOURCES/
cd /opt/dqiu/rpmbuild/SPECS
rpmbuild -ba libnbatch-0.2.0.spec
cd /opt/dqiu/rpmbuild/RPMS/x86_64/
rpm -ivh libnbatch-0.2.0-1.el5.x86_64.rpm
#####################################################################################
