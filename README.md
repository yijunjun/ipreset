# ipreset
实在受不了很多广告,特地reset掉，还我一个干净的世界
ip domain tcp reset
```golang
// 可选opts第一个参数表示函数堆栈层级
func NewStackErr(reason string, opts ...int) error {
	skip := 1
	if len(opts) > 0 {
		skip = opts[0]
	}
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return errors.New(reason)
	}
	fun := runtime.FuncForPC(pc)
	return &StackErr{
		reason: fmt.Sprintf(
			"[%v %v:%v] %v",
			path.Base(file),
			fun.Name(),
			line,
			reason,
		),
	}
}

```
