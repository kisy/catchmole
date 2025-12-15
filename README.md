# CatchMole

CatchMole 是一个高性能的局域网流量监控工具，基于 eBPF/Netlink 技术，提供设备级流量统计和连接追踪。

## 🚀 快速开始

### 1. 编译

```bash
git clone https://github.com/kisy/catchmole.git
cd catchmole
./build.sh
```

### 2. 运行

```bash
# 需要 root 权限
sudo ./bin/catchmole-amd64 -config catchmole.toml
```

访问 Web UI: `http://<ip>:8080`

## ⚙️ 配置 (catchmole.toml)

```toml
listen = ":8080"        # 监听地址
interface = "eth0"      # 监控接口
ignore_lan = true     # 是否忽略局域网内部流量(默认为 true, -lan 参数可开启监控)
interval = 1            # 刷新间隔(秒)

[devices]               # 设备别名
"aa:bb:cc:dd:ee:ff" = "My Phone"
```

## 📊 Grafana 集成

配置 Prometheus 抓取 `/metrics`，并导入 `grafana.json` 即可使用预置仪表盘。

## 📝 许可证

[GPL-2.0](LICENSE)
