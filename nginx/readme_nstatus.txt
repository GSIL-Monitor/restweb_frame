nginx_navi rpm����nstatus���񣩼��������������

#####################################################################################
���spec�ļ��У�
c-ares.spec
libcurl4.spec
libnaviutil.spec
libnstatus.spec
nginx_navi.spec
#####################################################################################

#####################################################################################
���src���У�
c-ares.tar.gz
curl.tar.gz
libnaviutil.tar.gz
libnstatus.tar.gz
nginx_navi/SOURCES/*
#####################################################################################

#####################################################################################
���������ϵΪ��
nginx_navi Requires libnaviutil���Լ�nginx-1.0.12��Ҫ�����Ŀ⣩
    libnaviutil Requires jansson libredisproxy
    libnstatus Requires libnaviutil libnstatus-devel
        libnstatus-devel Requires libcurl4
            libcurl4 Requires c-ares

��������ʾ����
1 ����c-ares rpm��
svn co http://gforge.1verge.net/svn/c-ares/trunk ./c-ares-1.7.5
cp c-ares-1.7.5/c-ares-1.7.5.spec /opt/dqiu/rpmbuild/SPECS
cp c-ares-1.7.5/c-ares-1.7.5.tar.gz /opt/dqiu/rpmbuild/SOURCES/
cd /opt/dqiu/rpmbuild/SPECS
rpmbuild -ba c-ares-1.7.5.spec
cd /opt/dqiu/rpmbuild/RPMS/x86_64/
rpm -ivh c-ares-1.7.5-1.el5.x86_64.rpm

2 ����curl rpm��
svn co http://gforge.1verge.net/svn/libcurl/trunk ./libcurl4-7.27.0
cp libcurl4-7.27.0/libcurl4-7.27.0.spec /opt/dqiu/rpmbuild/SPECS
cp libcurl4-7.27.0/curl-7.27.0.tar.gz /opt/dqiu/rpmbuild/SOURCES/
cp libcurl4-7.27.0/curl-7.27.0.patch /opt/dqiu/rpmbuild/SOURCES/
cd /opt/dqiu/rpmbuild/SPECS
rpmbuild -ba libcurl4-7.27.0.spec
cd /opt/dqiu/rpmbuild/RPMS/x86_64/
rpm -Uvh libcurl4-7.27.0-3.x86_64.rpm libcurl4-devel-7.27.0-3.x86_64.rpm

3 ����libnaviutil rpm��
����nginx_navi rpm����session���񣩼������������������һ��

4 ����libnstatus rpm��
svn co http://gforge.1verge.net/svn/nstatus/trunk ./libnstatus-0.2.0
tar -zcvf libnstatus-0.2.0.tar.gz libnstatus-0.2.0
cp libnstatus-0.2.0/rpmbuild/libnstatus-0.2.0.spec /opt/dqiu/rpmbuild/SPECS/
cp libnstatus-0.2.0.tar.gz /opt/dqiu/rpmbuild/SOURCES/
cd /opt/dqiu/rpmbuild/SPECS
rpmbuild -ba libnstatus-0.2.0.spec
cd /opt/dqiu/rpmbuild/RPMS/x86_64/
rpm -Uvh libnstatus-0.2.0-2.el5.x86_64.rpm libnstatus-devel-0.2.0-2.el5.x86_64.rpm

5 ����nginx_navi rpm��
����nginx_navi rpm����session���񣩼����������������������
#####################################################################################
