## wasm_export.hについて
UnitTestのビルド目的に、sdk_backdoor.hにてincludeしているファイル および その中に記述されている必要最低限の定義を記述する。
なお、UnitTest対象では参照していないため、実機ビルド時に参照する本物のファイルとする必要がない。

## 5フォルダについて
* edge-software-framework
* edge-software-framework-sensor
* evp-device-agent
* nuttx(デバイス名フォルダ以外)
* quirc

上記の5フォルダはUnitTestのビルド目的に、参照ファイルを格納したフォルダ。
UnitTestでは、ビルドを通すために不要なincludeは無効化した状態で格納。

## nuttx以下のデバイス名フォルダについて
* nuttx/T5
* nuttx/T3P
* nuttx/T3Ws

上記の3フォルダはUnitTestのビルド目的に、ビルド後に生成されるヘッダファイル(config.h)をデバイス別に格納したフォルダ。
使用した aitrios-sdk-device-manifest の SHA-1情報は以下。
<br>
Type: T5_EVT, T3P, T3Ws

```
commit 2a35bf9b445e302f732142c29bff546ea7211552 (HEAD -> develop, origin/develop, origin/HEAD)
Date:   Thu May 22 12:23:45 2025 +0900

Add config for systemapp.(build_env v1.0.8) (#1192)

**What's been fixed**
Add config for systemapp.(build_env v1.0.8).

for T3P/T3Ws
CONFIG_EXTERNAL_LARGE_HEAP_FILEIO
CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_IMX500

for T3R-S3/T5/T5_EVT
CONFIG_EXTERNAL_LARGE_HEAP_MEMORY_MAP
CONFIG_APP_EXTERNAL_SENSOR_AI_LIB_DEVICE_AIISP

**issue**
https://github.com/SonySemiconductorSolutions/aitrios-sdk-device-system-apps/issues/828

```

## ut_sched.hについて
task_create, task_deleteのmock内のプロトタイプ宣言を記述したもの。
<br>
InitialSettingAppとSystemAppで使用するため共通のヘッダファイルとして定義する。
また引数に指定している変数の定義も行っている。

