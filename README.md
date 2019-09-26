SPHINX for Android
==================

Building
--------

Create a file called `local.properties` with a single line, editing the path
to match your file system layout:

	sdk.dir=/path/to/android/sdk

Then execute Gradle:

	./gradlew build

The resulting debug APK will be here:

	app/build/outputs/apk/debug/app-debug.apk
