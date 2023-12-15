import hilog from '@ohos.hilog';
import testNapi from 'libentry.so';

@Entry
@Component
struct Index {
  @State message: string = 'Hello World';

  build() {
    Row() {
      Column() {
        Text("call native")
          .fontSize(50)
          .padding(16)
          .fontWeight(FontWeight.Bold)
          .backgroundColor(Color.White)
          .borderRadius(8)
          .onClick(() => {
            let result = testNapi.add(2, 3);
            this.message = `native:\n2+3=${result}`
            hilog.info(0x0000, 'testTag', 'Test NAPI 2 + 3 = %{public}d', result);
          })

        Text(this.message)
          .fontSize(24)
          .padding(16)
          .fontWeight(FontWeight.Normal)
      }
      .width('100%')
    }
    .height('100%')
    .backgroundColor('#F5F5F5')
  }
}
