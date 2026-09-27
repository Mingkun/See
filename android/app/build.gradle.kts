plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.mingkun.see"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.mingkun.see"
        minSdk = 26
        targetSdk = 34
        versionCode = 51
        versionName = "2.40"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("org.nanohttpd:nanohttpd:2.3.1")
    implementation("androidx.core:core:1.13.1")
}

// 网页版与 app 内页面共用同一份源：构建前把 static/index.html 同步进 assets，
// 避免两边长期分叉（历史坑：网页版落后 app 版很多个版本）。
val syncWebUI by tasks.registering(Copy::class) {
    from(rootProject.file("../static/index.html"))
    into(layout.projectDirectory.dir("src/main/assets"))
}
tasks.named("preBuild") { dependsOn(syncWebUI) }
