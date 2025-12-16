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
访问 Web UI: `http://<ip>:8080`

### 3. Systemd 部署 (非 Root 用户)

CatchMole 支持以普通用户身份运行，只需授予 `CAP_NET_ADMIN` 权限。

1. 修改 `catchmole.service` 中的 `User`, `Group`, `WorkingDirectory` 和 `ExecStart` 路径。
2. 安装服务：

```bash
sudo cp catchmole.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now catchmole
```

**注意**: `AmbientCapabilities=CAP_NET_ADMIN` 是必须的，它允许以非 root 用户监听 Conntrack 事件。

## ⚠️ 重要说明

CatchMole 基于 Linux conntrack 进行流量统计。某些硬件上 可能会因为硬件分流（Hardware Flow Offload）而统计不准确。

### 常见问题：有连接但无流量数据

如果程序运行正常（Web UI 可访问），能看到连接数但**所有流量显示为 0**，可能是因为 Linux 内核未开启 Conntrack 流量统计功能。

解决方法：

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

要永久生效，请在 `/etc/sysctl.conf` 中添加 `net.netfilter.nf_conntrack_acct=1`。

## ⚙️ 配置 (catchmole.toml)

```toml
listen = ":8080"        # 监听地址
interface = "eth0"      # 监控接口
ignore_lan = true       # 是否忽略局域网内部流量(默认为 true)
interval = 1            # 刷新间隔(秒)
flow_ttl = 60           # 流量记录缓存时间(秒)

[devices]               # 设备别名
"aa:bb:cc:dd:ee:ff" = "MyPhone"
```

## 📊 Grafana 集成

配置 Prometheus 抓取 `/metrics`，并导入 `grafana.json` 即可使用预置仪表盘。

## 📝 许可证

[GPL-2.0](LICENSE)
