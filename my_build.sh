JAVA8_HOME=`pwd`"/build/linux-x86_64-normal-server-release/images/j2sdk-image"
TARGET_OPENJ9_JVM=`pwd`"/patched_jdk"

rm -rf jerry_lib
rm -rf jerry_classes
rm ${TARGET_OPENJ9_JVM}/jre/lib/amd64/libjncrypto.so
rm ${TARGET_OPENJ9_JVM}/jre/lib/rt.jar


#put the original back
cp ${JAVA8_HOME}/jre/lib/amd64/libjncrypto.so ${TARGET_OPENJ9_JVM}/jre/lib/amd64/
cp ${JAVA8_HOME}/jre/lib/rt.jar ${TARGET_OPENJ9_JVM}/jre/lib/


mkdir jerry_lib
mkdir jerry_classes


gcc -fPIC  -c -I./jerry_openssl/openssl-1.0.2p/include  -I${JAVA8_HOME}/include/linux -I${JAVA8_HOME}/include -I./build/linux-x86_64-normal-server-release/jdk/gensrc_headers/  ./closed/adds/jdk/src/share/native/jdk/crypto/jniprovider/NativeCrypto.c     -o ./jerry_lib/OSSL.o




#newossl
#gcc -shared -m64 -o ./jerry_lib/libjncrypto.so  ./jerry_lib/OSSL.o -L./openssl -l:libssl.a -l:libcrypto.a -Xlinker -z -Xlinker origin -Xlinker -rpath -Xlinker \$ORIGIN
#oldossl
#gcc -shared -m64 -o ./jerry_lib/libjncrypto.so  ./jerry_lib/OSSL.o -L./jerry_openssl/openssl-1.0.2p/ -l:libssl.a -l:libcrypto.a -Xlinker -z -Xlinker origin -Xlinker -rpath -Xlinker \$ORIGIN
#withoutossl
gcc -shared -m64 -o ./jerry_lib/libjncrypto.so  ./jerry_lib/OSSL.o -Xlinker -z -Xlinker origin -Xlinker -rpath -Xlinker \$ORIGIN




#copy (unmodified) openssl library to the jdk
#cp ./openssl/libcrypto.so ${TARGET_OPENJ9_JVM}/jre/lib/amd64/



#compile jni loader for C library
${JAVA8_HOME}/bin/javac -cp ./closed/adds/jdk/src/share/classes/ -d jerry_classes ./closed/adds/jdk/src/share/classes/jdk/crypto/jniprovider/NativeCrypto.java



# copy the files into the jdk
rm ${TARGET_OPENJ9_JVM}/jre/lib/amd64/libjncrypto.so
cp ./jerry_lib/libjncrypto.so ${TARGET_OPENJ9_JVM}/jre/lib/amd64/




#update the jni interface for loading C functions
cd jerry_classes
jar uf ${TARGET_OPENJ9_JVM}/jre/lib/rt.jar  ./jdk/crypto/jniprovider/*.class
cd ..


