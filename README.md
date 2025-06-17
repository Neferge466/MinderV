# MinderV - 网络安全评估工具

MinderV 是一款网络安全评估工具，旨在帮助安全人员快速识别网络系统中的漏洞和风险点，并提供详细的评估报告和修复建议。

## 功能特点

- 🕵️‍♂️ **网络拓扑分析**：自动发现网络结构和数据流向
- 🔍 **漏洞扫描**：使用Nmap进行端口扫描和漏洞检测
- 📊 **风险评估**：基于扫描结果计算风险评分
- 📄 **报告生成**：导出详细评估报告（Word/文本/CSV格式）
- ⚙️ **配置管理**：灵活的配置文件支持多种扫描模式
- 🔄 **自动更新**：定期检查并提示更新

## 技术栈

- 核心语言：Java 21
- 依赖管理：Maven
- 日志系统：Log4j2
- 文档处理：Apache POI
- 网络工具：Java HttpClient
- XML处理：JAXB
- 加密模块：Java Cryptography Extension

## 快速开始

### 前提条件

- Java 21+ 环境
- Nmap 安装并配置路径
- Maven 3.8+

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/Neferge466/MinderV.git
cd MinderV

# 构建项目
mvn clean package

# 运行程序
java -jar target/MinderV-1.0.0.jar
```
配置文件说明
配置文件位于 src/main/resources/config.properties：
```
# Nmap路径配置
nmap.path=C:/Program Files (x86)/Nmap/nmap.exe

# 扫描目标配置
scan.target.ips=10.8.0.3
scan.target.domains=www.example.com
scan.mode=multi
scan.exclude=192.168.1.1,192.168.1.254

# 更新配置
update.url=https://api.minderv.com/version
update.interval=7

# 安全配置
encryption.key=mysecretkey123456
ssl.verify=false
```
使用示例
基本扫描
```
// 分析网络系统
SystemAnalyzer analyzer = new SystemAnalyzer();
NetworkSystem system = analyzer.analyzeSystem();

// 生成评估计划
AssessmentPlan plan = PlanGenerator.generatePlan(system);

// 执行漏洞扫描
VulnerabilityScanner scanner = new VulnerabilityScanner();
ScanResult scanResult = scanner.performScan(system);

// 风险评估
RiskAssessor assessor = new RiskAssessor();
RiskAssessment assessment = assessor.assess(system, scanResult);

// 生成报告
ReportGenerator reporter = new ReportGenerator();
reporter.generateReport(plan, scanResult, assessment);
```
导出扫描结果
```
// 导出文本格式
FileUtils.exportScanResults(scanResult, "network_scan");

// 导出CSV格式
FileUtils.exportScanResultsToCSV(scanResult, "network_scan");
```
项目结构
```
src/
├── main/
│   ├── java/
│   │   └── com/
│   │       └── minderv/
│   │           ├── core/                   # 核心功能
│   │           ├── monitor/                # 监控模块
│   │           ├── scanners/               # 扫描器模块
│   │           ├── utils/                  # 工具类
│   │           └── Main.java               # 主程序入口
│   └── resources/
│       └── config.properties               # 配置文件
└── test/                                   # 测试代码
    └── java/
        └── com/
            └── minderv/
                └── tests/                  # 单元测试
                    └── AppTest.java
```

许可证
本项目采用 MIT License。

MinderV
