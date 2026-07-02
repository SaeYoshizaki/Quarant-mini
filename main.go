package main

import (
	"encoding/json"
	"fmt"

	"quarant-mini/analyzer"
)

func main() {
	// analyzer.Run() を呼ぶ -> []Eventが返る -> main.goで表示する
	events := analyzer.Run()       // []Eventの内容をeventsにコピー
	for _, event := range events { // eventsの内容を一つずつeventに入れて処理
		b, err := json.Marshal(event) // Goの構造体のデータをjson形式に変換して返す
		if err != nil {
			fmt.Println("failed to encode event:", err)
			continue
		}
		fmt.Println(string(b)) // Marshalの戻り値はbyte[]形式なので、stringにしないと数値で出力されてしまう
	}
}
