rm -rf build
# input your android ndk root directory
export ANDROID_NDK_ROOT=
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../arch/android/android-toolchain-armeabi-v7a.cmake -DCMAKE_SHARED=true ../
make -j8
