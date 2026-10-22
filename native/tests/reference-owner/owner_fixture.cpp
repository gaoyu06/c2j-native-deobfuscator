#include <jni.h>
extern "C" JNIEXPORT jint JNICALL Java_fixture_OwnerFixture_run(JNIEnv* e,jclass self) {
 auto loader=e->GetStaticMethodID(self,"resolve","(Ljava/lang/String;)Ljava/lang/Class;");
 auto alias=e->NewStringUTF("LimitedLemon");
 auto target=static_cast<jclass>(e->CallStaticObjectMethod(self,loader,alias));
 auto local=static_cast<jclass>(e->NewLocalRef(target));
 auto mid=e->GetStaticMethodID(local,"x","(II)I");
 auto fid=e->GetStaticFieldID(local,"field","I");
 auto value=e->CallStaticIntMethod(local,mid,41,2);
 if(e->GetStaticIntField(local,fid)!=7)return -1;
 e->DeleteLocalRef(local);e->DeleteLocalRef(target);e->DeleteLocalRef(alias);
 return value;
}
