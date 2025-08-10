#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI流量检测系统 - Windows服务管理器
用于将Flask应用注册为Windows系统服务，实现开机自启动和后台运行
"""

import win32serviceutil
import win32service
import win32event
import win32api
import subprocess
import sys
import os
import time
import logging
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("ai_detector_service.log"), logging.StreamHandler()],
)

logger = logging.getLogger("AIDetectorService")


class AITrafficDetectorService(win32serviceutil.ServiceFramework):
    """AI流量检测系统Windows服务类"""

    _svc_name_ = "AITrafficDetector"
    _svc_display_name_ = "AI Traffic Detector Service"
    _svc_description_ = (
        "AI-based network traffic analysis and anomaly detection service"
    )

    def __init__(self, args):
        """初始化服务"""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_alive = True
        self.process = None

        # 服务配置
        self.service_dir = Path(__file__).parent
        self.python_exe = sys.executable
        self.app_script = self.service_dir / "start_server.py"

        logger.info(f"服务初始化完成")
        logger.info(f"Python路径: {self.python_exe}")
        logger.info(f"应用脚本: {self.app_script}")

    def SvcStop(self):
        """停止服务"""
        logger.info("正在停止AI流量检测服务...")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        # 终止Flask进程
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=10)
                logger.info("Flask应用已停止")
            except Exception as e:
                logger.error(f"停止Flask应用时发生错误: {e}")
                try:
                    self.process.kill()
                except:
                    pass

        self.is_alive = False
        win32event.SetEvent(self.hWaitStop)
        logger.info("AI流量检测服务已停止")

    def SvcDoRun(self):
        """运行服务主逻辑"""
        try:
            logger.info("正在启动AI流量检测服务...")

            # 设置工作目录
            os.chdir(str(self.service_dir))
            logger.info(f"工作目录设置为: {self.service_dir}")

            # 启动Flask应用
            self._start_flask_app()

            # 监控服务状态
            self._monitor_service()

        except Exception as e:
            logger.error(f"服务运行时发生错误: {e}")
            self.SvcStop()

    def _start_flask_app(self):
        """启动Flask应用"""
        try:
            cmd = [str(self.python_exe), str(self.app_script)]
            logger.info(f"执行命令: {' '.join(cmd)}")

            # 启动子进程
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.service_dir),
                creationflags=subprocess.CREATE_NO_WINDOW,  # 后台运行，不显示窗口
            )

            logger.info(f"Flask应用已启动，进程ID: {self.process.pid}")

            # 等待应用启动
            time.sleep(3)

            if self.process.poll() is None:
                logger.info("Flask应用启动成功")
            else:
                stdout, stderr = self.process.communicate()
                logger.error(f"Flask应用启动失败")
                logger.error(f"stdout: {stdout.decode('utf-8', errors='ignore')}")
                logger.error(f"stderr: {stderr.decode('utf-8', errors='ignore')}")
                raise Exception("Flask应用启动失败")

        except Exception as e:
            logger.error(f"启动Flask应用时发生错误: {e}")
            raise

    def _monitor_service(self):
        """监控服务状态"""
        logger.info("开始监控服务状态...")

        while self.is_alive:
            try:
                # 检查停止事件
                rc = win32event.WaitForSingleObject(self.hWaitStop, 1000)  # 等待1秒

                if rc == win32event.WAIT_OBJECT_0:
                    # 接收到停止信号
                    break

                # 检查Flask进程状态
                if self.process and self.process.poll() is not None:
                    logger.warning("Flask进程意外退出，尝试重启...")
                    stdout, stderr = self.process.communicate()
                    logger.error(f"进程输出: {stdout.decode('utf-8', errors='ignore')}")
                    logger.error(f"进程错误: {stderr.decode('utf-8', errors='ignore')}")

                    # 重启Flask应用
                    time.sleep(5)  # 等待5秒再重启
                    self._start_flask_app()

            except Exception as e:
                logger.error(f"监控服务时发生错误: {e}")
                time.sleep(5)

        logger.info("服务监控已停止")


def install_service():
    """安装Windows服务"""
    try:
        # 安装服务
        win32serviceutil.InstallService(
            AITrafficDetectorService._svc_reg_class_,
            AITrafficDetectorService._svc_name_,
            AITrafficDetectorService._svc_display_name_,
            description=AITrafficDetectorService._svc_description_,
        )

        # 设置服务为自动启动
        import win32service

        hscm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_ALL_ACCESS
        )
        hs = win32service.OpenService(
            hscm, AITrafficDetectorService._svc_name_, win32service.SERVICE_ALL_ACCESS
        )

        win32service.ChangeServiceConfig(
            hs,
            win32service.SERVICE_NO_CHANGE,  # 服务类型
            win32service.SERVICE_AUTO_START,  # 启动类型：自动
            win32service.SERVICE_NO_CHANGE,  # 错误控制
            None,
            None,
            0,
            None,
            None,
            None,
            AITrafficDetectorService._svc_display_name_,
        )

        win32service.CloseServiceHandle(hs)
        win32service.CloseServiceHandle(hscm)

        print("✅ AI流量检测服务安装成功！")
        print("🔧 服务已设置为开机自动启动")
        print(f"📝 服务名称: {AITrafficDetectorService._svc_name_}")
        print(f"🏷️ 显示名称: {AITrafficDetectorService._svc_display_name_}")

        return True

    except Exception as e:
        print(f"❌ 服务安装失败: {e}")
        return False


def uninstall_service():
    """卸载Windows服务"""
    try:
        win32serviceutil.RemoveService(AITrafficDetectorService._svc_name_)
        print("✅ AI流量检测服务卸载成功！")
        return True
    except Exception as e:
        print(f"❌ 服务卸载失败: {e}")
        return False


def start_service():
    """启动Windows服务"""
    try:
        win32serviceutil.StartService(AITrafficDetectorService._svc_name_)
        print("✅ AI流量检测服务启动成功！")
        print("🌐 系统现在可以通过网络访问: http://localhost:5000")
        return True
    except Exception as e:
        print(f"❌ 服务启动失败: {e}")
        return False


def stop_service():
    """停止Windows服务"""
    try:
        win32serviceutil.StopService(AITrafficDetectorService._svc_name_)
        print("✅ AI流量检测服务停止成功！")
        return True
    except Exception as e:
        print(f"❌ 服务停止失败: {e}")
        return False


def restart_service():
    """重启Windows服务"""
    print("🔄 正在重启AI流量检测服务...")
    stop_service()
    time.sleep(3)
    return start_service()


def service_status():
    """查看服务状态"""
    try:
        import win32service

        hscm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
        )
        hs = win32service.OpenService(
            hscm, AITrafficDetectorService._svc_name_, win32service.SERVICE_QUERY_STATUS
        )

        status = win32service.QueryServiceStatusEx(hs)

        status_map = {
            win32service.SERVICE_STOPPED: "已停止",
            win32service.SERVICE_START_PENDING: "正在启动",
            win32service.SERVICE_STOP_PENDING: "正在停止",
            win32service.SERVICE_RUNNING: "正在运行",
            win32service.SERVICE_CONTINUE_PENDING: "正在继续",
            win32service.SERVICE_PAUSE_PENDING: "正在暂停",
            win32service.SERVICE_PAUSED: "已暂停",
        }

        current_status = status_map.get(status["CurrentState"], "未知状态")

        print("📊 AI流量检测服务状态:")
        print(f"   状态: {current_status}")
        print(f"   进程ID: {status.get('ProcessId', 'N/A')}")
        print(f"   服务类型: {status['ServiceType']}")

        win32service.CloseServiceHandle(hs)
        win32service.CloseServiceHandle(hscm)

        return status["CurrentState"] == win32service.SERVICE_RUNNING

    except Exception as e:
        print(f"❌ 查询服务状态失败: {e}")
        return False


def main():
    """主函数 - 命令行界面"""
    if len(sys.argv) == 1:
        print("🤖 AI流量检测系统 - Windows服务管理器")
        print("=" * 50)
        print("📋 可用命令:")
        print("  install   - 安装服务")
        print("  uninstall - 卸载服务")
        print("  start     - 启动服务")
        print("  stop      - 停止服务")
        print("  restart   - 重启服务")
        print("  status    - 查看状态")
        print("=" * 50)
        print("💡 使用示例:")
        print("  python service_manager.py install")
        print("  python service_manager.py start")
        print("=" * 50)
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "install":
        if install_service():
            print("\n🎉 下一步:")
            print("  python service_manager.py start  # 启动服务")

    elif command == "uninstall":
        # 先停止服务
        try:
            stop_service()
        except:
            pass
        uninstall_service()

    elif command == "start":
        start_service()

    elif command == "stop":
        stop_service()

    elif command == "restart":
        restart_service()

    elif command == "status":
        is_running = service_status()
        if is_running:
            print("🌐 访问地址: http://localhost:5000")
        else:
            print("💡 使用 'python service_manager.py start' 启动服务")

    else:
        print(f"❌ 未知命令: {command}")
        print("💡 运行 'python service_manager.py' 查看帮助")


if __name__ == "__main__":
    # 检查是否以服务模式运行
    if len(sys.argv) > 1 and sys.argv[1] in [
        "install",
        "uninstall",
        "start",
        "stop",
        "restart",
        "status",
    ]:
        main()
    else:
        # 作为Windows服务运行
        win32serviceutil.HandleCommandLine(AITrafficDetectorService)
