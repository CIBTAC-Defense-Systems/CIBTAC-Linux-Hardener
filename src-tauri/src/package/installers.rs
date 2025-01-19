use super::types::{InstallationReport, InstallationResult};
use crate::sandbox::Sandbox;
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[async_trait]
pub trait PackageInstaller {
    async fn install(
        &self,
        package: &Package,
        install_dir: &Path,
        sandbox: &Sandbox,
    ) -> Result<InstallationResult, PackageError>;

    async fn verify_installation(&self, result: &InstallationResult) -> Result<bool, PackageError>;
    async fn rollback(&self, package: &Package) -> Result<(), PackageError>;
}

pub struct AptInstaller {
    config: AptConfig,
}

pub struct DnfInstaller {
    config: DnfConfig,
}

pub struct PipInstaller {
    config: PipConfig,
}

pub struct NpmInstaller {
    config: NpmConfig,
}

#[async_trait]
impl PackageInstaller for AptInstaller {
    async fn install(
        &self,
        package: &Package,
        install_dir: &Path,
        sandbox: &Sandbox,
    ) -> Result<InstallationResult, PackageError> {
        // Prepare APT environment
        self.prepare_apt_environment(sandbox).await?;

        // Update package cache
        sandbox.execute("apt-get update").await?;

        // Install package
        let cmd = format!(
            "apt-get install -y --no-install-recommends {}={}",
            package.name, package.version
        );
        sandbox.execute(&cmd).await?;

        // Collect installation information
        let files_installed = self.get_installed_files(package).await?;
        let configuration = self.extract_apt_configuration(package).await?;
        let installation_report = self.generate_installation_report(package).await?;

        Ok(InstallationResult {
            install_path: install_dir.to_path_buf(),
            files_installed,
            configuration,
            monitor_config: Some(self.config.monitoring_config.clone()),
            installation_report,
        })
    }

    async fn verify_installation(&self, result: &InstallationResult) -> Result<bool, PackageError> {
        // Verify package files
        self.verify_package_files(&result.files_installed).await?;

        // Verify package status
        self.verify_package_status(&result.configuration).await?;

        // Verify dependencies
        self.verify_dependencies(&result.configuration).await?;

        Ok(true)
    }

    async fn rollback(&self, package: &Package) -> Result<(), PackageError> {
        let cmd = format!("apt-get remove -y {}", package.name);
        sandbox.execute(&cmd).await?;
        Ok(())
    }
}

#[async_trait]
impl PackageInstaller for PipInstaller {
    async fn install(
        &self,
        package: &Package,
        install_dir: &Path,
        sandbox: &Sandbox,
    ) -> Result<InstallationResult, PackageError> {
        // Set up virtual environment if configured
        if self.config.use_virtualenv {
            self.setup_virtualenv(install_dir, sandbox).await?;
        }

        // Install package
        let cmd = format!("pip install {}=={}", package.name, package.version);
        sandbox.execute(&cmd).await?;

        // Collect installation information
        let files_installed = self.get_installed_files(package).await?;
        let configuration = self.extract_pip_configuration(package).await?;
        let installation_report = self.generate_installation_report(package).await?;

        Ok(InstallationResult {
            install_path: install_dir.to_path_buf(),
            files_installed,
            configuration,
            monitor_config: Some(self.config.monitoring_config.clone()),
            installation_report,
        })
    }

    async fn verify_installation(&self, result: &InstallationResult) -> Result<bool, PackageError> {
        // Verify package installation
        self.verify_pip_installation(&result.configuration).await?;

        // Verify dependencies
        self.verify_pip_dependencies(&result.configuration).await?;

        Ok(true)
    }

    async fn rollback(&self, package: &Package) -> Result<(), PackageError> {
        let cmd = format!("pip uninstall -y {}", package.name);
        sandbox.execute(&cmd).await?;
        Ok(())
    }
}

// Factory for creating appropriate installer
pub struct InstallerFactory;

impl InstallerFactory {
    pub fn create_installer(package_source: &PackageSource) -> Box<dyn PackageInstaller> {
        match package_source {
            PackageSource::Apt(_) => Box::new(AptInstaller::new()),
            PackageSource::Dnf(_) => Box::new(DnfInstaller::new()),
            PackageSource::Pip(_) => Box::new(PipInstaller::new()),
            PackageSource::Npm(_) => Box::new(NpmInstaller::new()),
            _ => Box::new(GenericInstaller::new()),
        }
    }
}
