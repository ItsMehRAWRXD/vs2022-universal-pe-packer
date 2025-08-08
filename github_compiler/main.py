#!/usr/bin/env python3
"""
GitHub Compiler GUI - initial prototype
A native cross-platform GUI that acts as a middle-man for working with multiple GitHub repositories.
Currently implemented features:
* Scans the current working directory for git repositories and lists them.
* Provides buttons for Clone, Pull, Push, and Compile (logic to be filled in upcoming iterations).
Dependencies: PyQt5, GitPython
"""

import sys
import subprocess
from pathlib import Path
import shutil
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QListWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QMessageBox,
    QInputDialog,
)
from PyQt5.QtCore import Qt

try:
    from git import Repo, GitCommandError
except ImportError:
    Repo = None  # GitPython not installed yet; runtime check handled later

WORKSPACE_PATH = Path.cwd()


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GitHub Compiler GUI (Prototype)")
        self.resize(800, 600)
        self._build_ui()
        self._scan_repositories()

    # --------------------------- UI SETUP --------------------------- #

    def _build_ui(self):
        main_layout = QVBoxLayout()

        header = QLabel("Git Repositories in Workspace")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-weight: bold; font-size: 18px;")
        main_layout.addWidget(header)

        self.repo_list = QListWidget()
        main_layout.addWidget(self.repo_list, stretch=1)

        btn_layout = QHBoxLayout()
        self.clone_btn = QPushButton("Clone")
        self.pull_btn = QPushButton("Pull")
        self.push_btn = QPushButton("Push")
        self.compile_btn = QPushButton("Compile")
        self.upload_btn = QPushButton("Upload Artifacts")
        for btn in (self.clone_btn, self.pull_btn, self.push_btn, self.compile_btn, self.upload_btn):
            btn_layout.addWidget(btn)
        main_layout.addLayout(btn_layout)

        self.setLayout(main_layout)

        # Connect signals
        self.clone_btn.clicked.connect(self._clone_repository)
        self.pull_btn.clicked.connect(self._pull_repository)
        self.push_btn.clicked.connect(self._push_repository)
        self.compile_btn.clicked.connect(self._compile_repository)
        self.upload_btn.clicked.connect(self._upload_artifacts)

    # --------------------------- CORE LOGIC --------------------------- #

    def _scan_repositories(self):
        """Populate the list widget with directories that contain a .git folder."""
        self.repo_list.clear()
        for item in sorted(WORKSPACE_PATH.iterdir()):
            if (item / ".git").is_dir():
                self.repo_list.addItem(item.name)

    def _selected_repo_path(self) -> Path | None:
        item = self.repo_list.currentItem()
        if not item:
            QMessageBox.warning(self, "No Repository Selected", "Please select a repository first.")
            return None
        return WORKSPACE_PATH / item.text()

    # --------------------------- ACTIONS --------------------------- #

    def _clone_repository(self):
        if Repo is None:
            QMessageBox.critical(self, "Dependency Missing", "GitPython is not installed. Please run:\n  pip install GitPython")
            return

        url, ok = QInputDialog.getText(self, "Clone Repository", "Enter Git URL:")
        if ok and url:
            dest_path = WORKSPACE_PATH / Path(url).stem
            try:
                Repo.clone_from(url, dest_path)
                QMessageBox.information(self, "Clone Successful", f"Repository cloned to {dest_path}")
                self._scan_repositories()
            except GitCommandError as e:
                QMessageBox.critical(self, "Clone Failed", str(e))

    def _pull_repository(self):
        if Repo is None:
            QMessageBox.critical(self, "Dependency Missing", "GitPython is not installed. Please run:\n  pip install GitPython")
            return
        repo_path = self._selected_repo_path()
        if not repo_path:
            return
        try:
            repo = Repo(repo_path)
            origin = repo.remotes.origin
            origin.pull()
            QMessageBox.information(self, "Pull Successful", "Repository updated.")
        except Exception as e:
            QMessageBox.critical(self, "Pull Failed", str(e))

    def _push_repository(self):
        if Repo is None:
            QMessageBox.critical(self, "Dependency Missing", "GitPython is not installed. Please run:\n  pip install GitPython")
            return
        repo_path = self._selected_repo_path()
        if not repo_path:
            return
        try:
            repo = Repo(repo_path)
            origin = repo.remotes.origin
            origin.push()
            QMessageBox.information(self, "Push Successful", "Repository pushed to remote.")
        except Exception as e:
            QMessageBox.critical(self, "Push Failed", str(e))

    def _compile_repository(self):
        repo_path = self._selected_repo_path()
        if not repo_path:
            return
        # Very naive compile strategy for prototype purposes
        build_commands = [
            ("make", []),
            ("cmake", ["-S", ".", "-B", "build"]),
            ("cargo", ["build"]),
        ]
        for cmd, args in build_commands:
            if (repo_path / "Makefile").exists() and cmd == "make":
                self._run_external_command([cmd] + args, repo_path)
                return
            if (repo_path / "CMakeLists.txt").exists() and cmd == "cmake":
                self._run_external_command([cmd] + args, repo_path)
                return
            if (repo_path / "Cargo.toml").exists() and cmd == "cargo":
                self._run_external_command([cmd] + args, repo_path)
                return
        QMessageBox.information(self, "Compile", "No known build system detected for this repository.")

    def _upload_artifacts(self):
        """Copy a chosen artifacts folder into the repo, commit, and push it."""
        if Repo is None:
            QMessageBox.critical(self, "Dependency Missing", "GitPython is not installed. Please run:\n  pip install GitPython")
            return

        repo_path = self._selected_repo_path()
        if not repo_path:
            return

        src_dir_str, ok = QInputDialog.getText(
            self,
            "Artifact Directory",
            "Enter path to artifact folder (relative to repo or absolute):",
        )
        if not ok or not src_dir_str:
            return

        src_dir = Path(src_dir_str)
        if not src_dir.is_absolute():
            src_dir = repo_path / src_dir

        if not src_dir.exists():
            QMessageBox.warning(self, "Path Not Found", f"{src_dir} does not exist.")
            return

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        dest_dir = repo_path / "artifacts" / timestamp

        try:
            shutil.copytree(src_dir, dest_dir, dirs_exist_ok=True)

            repo = Repo(repo_path)
            repo.index.add([str(dest_dir.relative_to(repo_path))])
            repo.index.commit(f"Add compiled artifacts ({timestamp})")
            repo.remotes.origin.push()

            QMessageBox.information(
                self,
                "Upload Successful",
                f"Artifacts copied to {dest_dir} and pushed to remote.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Upload Failed", str(e))

    # --------------------------- UTILITIES --------------------------- #

    def _run_external_command(self, command: list[str], cwd: Path):
        """Run a command and show its output in a dialog."""
        try:
            completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
            output = completed.stdout + "\n" + completed.stderr
            QMessageBox.information(self, "Command Output", output[:5000] or "(No output)")
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Command Failed", e.stderr or str(e))


# --------------------------- ENTRY POINT --------------------------- #

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()