## 关于

本仓库存储`MsgEx.db`解密相关内容。

## 如何使用

在 <https://github.com/QQBackup/MsgEx/releases/tag/latest> 中下载对应你的电脑架构的版本（如果不确定，可以都下载下来试试）

在`MsgEx.db`所在目录打开`cmd`，输入`MsgEx.exe MsgEx.db 你的QQ号`，运行。

### 从 TXT 反向生成 MsgEx.db

如果 TXT 是本工具导出的消息记录，或形如 `用户:3058575(lifanxi)`、`消息组:我的好友`、`消息对象:1827488(林风)` 的旧版导出格式，可以使用导入模式重新生成一个 `MsgEx.db`：

```bash
MsgEx.exe --import input.txt 你的QQ号 MsgEx.db
```

反向生成会恢复 TXT 中可见的消息类型、消息对象、时间、显示名和正文。原始数据库中没有导出到 TXT 的内部字段（例如部分群/讨论组消息的 from/to 数值、字体尾部数据等）会使用默认值填充。

## 贡献样本

由于我没有`msg.db`及`MsgEx.db`的样本，难以对其进行更进一步的分析，如果您愿意提供可以直接在该仓库的 Issues 区联系。

## 相关链接

- <https://bbs.kanxue.com/thread-29098.htm>
- <https://bbs.kanxue.com/thread-37109-1.htm>
- <https://bbs.kanxue.com/thread-51946-1.htm>
