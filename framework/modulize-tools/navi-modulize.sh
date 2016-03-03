#!/bin/env bash
if [ $# -lt 3 ]
then
	echo "$0 module-name module-version module-lib-version [method ...]"
	exit 1
fi

module_name=$1
module_ver=$2
module_libver=$3

module_name=`echo $module_name | tr [A-Z] [a-z]`

if [ ${module_name:0:1} != "n" ];then
	module_name=n$module_name
fi

subdir=lib${module_name}-${module_ver}
mkdir -p ${subdir}

module_case_name=`echo $module_name | tr [a-z] [A-Z]`
module_libver=`echo $module_libver|tr [.] [:]`

shift 3
while [ $# -ge 1 ]
do
	if [ $method_list ]
	then
		method_list="$method_list\",\"$1"
	else
		method_list="\"$1"
	fi

	cat << AA

NAVI_MODULE_METHOD(${module_name},$1,module,request)
{
	return NAVI_OK;
}
AA

	shift
done>${module_name}.method

if [ $method_list ]
then
	method_list=$method_list"\""
fi

echo $method_list

echo "s/%{MODULE_NAME}/${module_name}/g"  > change_var.sed
echo "s/%{MODULE_CASE_NAME}/${module_case_name}/g" >> change_var.sed
echo "s/%{MODULE_VERSION}/${module_ver}/g" >> change_var.sed
echo "s/%{MODULE_LIB_VERSION}/${module_libver}/g" >> change_var.sed
echo "s/%{METHOD_LIST}/${method_list}/g" >> change_var.sed
echo "s/%{MODULE_UCASE}/${module_case_name}/g" >> change_var.sed
echo "s/%{MODULE_LCASE}/${module_name}/g" >> change_var.sed

sed -f change_var.sed configure.ac.tpl > ${subdir}/configure.ac
sed -f change_var.sed Makefile.am.tpl > ${subdir}/Makefile.am
sed -f change_var.sed module.json.tpl > ${subdir}/${module_name}.json
sed -f change_var.sed module.rpmspec.tpl > ${subdir}/lib${module_name}-${module_ver}.spec
sed -f change_var.sed module.c.tpl > ${subdir}/navi_${module_name}_module.c
sed -f change_var.sed module.log.c.tpl > ${subdir}/${module_name}_log.c
sed -f change_var.sed module.log.h.tpl > ${subdir}/${module_name}_log.h

cat ${module_name}.method >> ${subdir}/navi_${module_name}_module.c

rm -f ${module_name}.method change_var.sed
cd ${subdir}
autoreconf --install --force
rm -rf autom4te.cache

