plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.tuberlin.mobilewallet"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.tuberlin.mobilewallet"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.1"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {

    implementation("androidx.core:core-ktx:1.10.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.11.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")

    implementation("androidx.camera:camera-lifecycle:1.4.0")
    implementation("androidx.camera:camera-view:1.4.0")
    implementation("androidx.camera:camera-camera2:1.4.0")
    implementation("androidx.camera:camera-core:1.4.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.google.mlkit:vision-common:17.3.0")
    implementation("com.google.android.gms:play-services-mlkit-barcode-scanning:18.3.1")
    implementation("androidx.preference:preference-ktx:1.2.1")

    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("io.jsonwebtoken:jjwt-impl:0.10.5")
    implementation("io.jsonwebtoken:jjwt-orgjson:0.10.5")
    implementation("io.jsonwebtoken:jjwt-api:0.10.5")
    implementation("androidx.compose.runtime:runtime-livedata:1.7.6")

    implementation("com.google.code.gson:gson:2.10.1")
    implementation("androidx.navigation:navigation-compose:2.8.5")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.11.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    //QR/Barcode generation
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.simonsickle:composed-barcodes:1.3.0")

    // Uniffi
    implementation("net.java.dev.jna:jna:5.7.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4")
}