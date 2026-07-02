use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "tokio")]
use std::io::Read;

#[cfg(feature = "tokio")]
use encoding_rs_io::DecodeReaderBytes;
use tempfile::{NamedTempFile, TempPath};
use tracing::{debug, warn};

pub use crate::locked_file::*;
pub use crate::path::*;

pub mod cachedir;
pub mod link;
mod locked_file;
mod path;
pub mod which;

/// Attempt to check if the two paths refer to the same file.
///
/// Returns `Some(true)` if the files are missing, but would be the same if they existed.
pub fn is_same_file_allow_missing(left: &Path, right: &Path) -> Option<bool> {
    // First, check an exact path comparison.
    if left == right {
        return Some(true);
    }

    // Second, check the files directly.
    if let Ok(value) = same_file::is_same_file(left, right) {
        return Some(value);
    }

    // Often, one of the directories won't exist yet so perform the comparison up a level.
    if let (Some(left_parent), Some(right_parent), Some(left_name), Some(right_name)) = (
        left.parent(),
        right.parent(),
        left.file_name(),
        right.file_name(),
    ) {
        match same_file::is_same_file(left_parent, right_parent) {
            Ok(true) => return Some(left_name == right_name),
            Ok(false) => return Some(false),
            _ => (),
        }
    }

    // We couldn't determine if they're the same.
    None
}

/// Reads data from the path and requires that it be valid UTF-8 or UTF-16.
///
/// This uses BOM sniffing to determine if the data should be transcoded from UTF-16 to Rust's
/// `String` type (which uses UTF-8).
///
/// This should generally only be used when one specifically wants to support reading UTF-16
/// transparently.
///
/// If the file path is `-`, then contents are read from stdin instead.
#[cfg(feature = "tokio")]
pub async fn read_to_string_transcode(path: impl AsRef<Path>) -> std::io::Result<String> {
    let path = path.as_ref();
    let raw = if path == Path::new("-") {
        let mut buf = Vec::with_capacity(1024);
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs_err::tokio::read(path).await?
    };
    let mut buf = String::with_capacity(1024);
    DecodeReaderBytes::new(&*raw)
        .read_to_string(&mut buf)
        .map_err(|err| {
            let path = path.display();
            std::io::Error::other(format!("failed to decode file {path}: {err}"))
        })?;
    Ok(buf)
}

/// Create a junction at `path` pointing to `target`.
///
/// Junctions can be silently broken when involving network paths or non-NTFS filesystems.
///
/// If creation fails but leaves behind an empty directory, it is cleaned up and the original
/// creation error is propagated.
#[cfg(windows)]
fn create_junction(target: &Path, path: &Path) -> std::io::Result<()> {
    use windows::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER,
        ERROR_INVALID_REPARSE_DATA, ERROR_NOT_A_REPARSE_POINT, WIN32_ERROR,
    };

    let create_result = junction::create(target, path);

    match path.metadata() {
        Ok(_) if create_result.is_ok() => Ok(()),
        Ok(_) => {
            // Creation failed but left behind an empty directory. Only clean
            // it up if the directory wasn't already there before we tried.
            if let Err(ref create_err) = create_result {
                if !matches!(
                    create_err
                        .raw_os_error()
                        .map(|err| WIN32_ERROR(err.cast_unsigned())),
                    Some(ERROR_ALREADY_EXISTS)
                ) {
                    // Not a junction (metadata succeeded normally), just
                    // an empty directory left behind by junction::create.
                    let _ = fs_err::remove_dir(path);
                }
            }
            create_result
        }
        Err(err)
            if matches!(
                err.raw_os_error()
                    .map(|err| WIN32_ERROR(err.cast_unsigned())),
                Some(
                    ERROR_INVALID_PARAMETER
                        | ERROR_INVALID_NAME
                        | ERROR_NOT_A_REPARSE_POINT
                        | ERROR_INVALID_REPARSE_DATA
                )
            ) =>
        {
            // Broken reparse point.
            let _ = fs_err::remove_dir(path);
            Err(create_result.err().unwrap_or(err))
        }
        Err(err) => Err(create_result.err().unwrap_or(err)),
    }
}

/// Create a directory link at `dst` pointing to `src`, replacing any existing link.
///
/// On Windows, this normally creates an NTFS junction, since junctions don't
/// require elevated privileges. When running under Wine, which doesn't implement
/// the reparse-point ioctl that junction creation depends on, this transparently
/// creates a Windows directory symbolic link instead via `CreateSymbolicLinkW`
/// (Wine maps that to a Unix symlink, so it succeeds without privileges).
///
/// The operation is _not_ atomic: any existing entry at `dst` is removed first,
/// then the new link is created at the same path.
///
/// Note that the source must be a directory.
///
/// Changes to this function should be reflected in [`create_symlink`].
#[cfg(windows)]
pub fn replace_symlink(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();

    if src.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Cannot create a directory link for {}: is not a directory",
                src.display()
            ),
        ));
    }

    if uv_windows::is_wine() {
        replace_with_symlink_dir(src, dst)
    } else {
        replace_with_junction(src, dst)
    }
}

#[cfg(windows)]
fn replace_with_junction(src: &Path, dst: &Path) -> std::io::Result<()> {
    // Remove the existing junction, if any.
    match fs_err::remove_dir(dst) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    // Replace it with a new junction.
    create_junction(src, dst)
}

#[cfg(windows)]
fn replace_with_symlink_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    // Best-effort removal of any existing entry. The destination may be a
    // directory, file, or symlink, so try the directory removal first and
    // fall back to file removal if that fails.
    match fs_err::remove_dir_all(dst) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => match fs_err::remove_file(dst) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        },
    }

    fs_err::os::windows::fs::symlink_dir(dunce::simplified(src), dunce::simplified(dst))
}

/// Create a symlink at `dst` pointing to `src`, replacing any existing symlink if necessary.
///
/// On Unix, this method creates a temporary file, then moves it into place.
#[cfg(unix)]
pub fn replace_symlink(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    // Attempt to create the symlink directly.
    match fs_err::os::unix::fs::symlink(src.as_ref(), dst.as_ref()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Create a symlink, using a temporary file to ensure atomicity.
            let temp_dir = tempfile::tempdir_in(dst.as_ref().parent().unwrap())?;
            let temp_file = temp_dir.path().join("link");
            fs_err::os::unix::fs::symlink(src, &temp_file)?;

            // Move the symlink into the target location.
            fs_err::rename(&temp_file, dst.as_ref())?;

            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Create a directory link at `dst` pointing to `src`.
///
/// On Windows, this normally creates an NTFS junction, falling back to a Windows
/// directory symbolic link when running under Wine. See [`replace_symlink`] for
/// the rationale.
///
/// Note that the source must be a directory.
///
/// Changes to this function should be reflected in [`replace_symlink`].
#[cfg(windows)]
pub fn create_symlink(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();

    if src.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Cannot create a directory link for {}: is not a directory",
                src.display()
            ),
        ));
    }

    if uv_windows::is_wine() {
        fs_err::os::windows::fs::symlink_dir(dunce::simplified(src), dunce::simplified(dst))
    } else {
        create_junction(src, dst)
    }
}

/// Create a symlink at `dst` pointing to `src`.
#[cfg(unix)]
pub fn create_symlink(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    fs_err::os::unix::fs::symlink(src.as_ref(), dst.as_ref())
}

/// Remove a symbolic link at `path` without following its target.
pub fn remove_symlink(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();

    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTypeExt;

        if fs_err::symlink_metadata(path)?.file_type().is_symlink_dir() {
            return fs_err::remove_dir(path);
        }
    }

    fs_err::remove_file(path)
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::os::windows::ffi::OsStrExt;

    use super::*;

    #[test]
    fn fs_err_read_link_reads_created_directory_link() -> std::io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("target");
        fs_err::create_dir(&target)?;
        let link = tempdir.path().join("link");

        create_symlink(&target, &link)?;

        assert_eq!(
            verbatim_path(&fs_err::read_link(&link)?),
            verbatim_path(&target)
        );
        Ok(())
    }

    #[test]
    fn fs_err_read_link_reads_long_junction_target() -> std::io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let mut target = tempdir.path().join("target");
        while target.as_os_str().encode_wide().count() < 257 {
            target.push("long-path-component");
        }
        fs_err::create_dir_all(&target)?;
        let link = tempdir.path().join("link");

        create_symlink(&target, &link)?;

        let link_target = fs_err::read_link(&link)?;
        assert_eq!(verbatim_path(&link_target), verbatim_path(&target));
        Ok(())
    }

    #[test]
    fn create_junction_from_smb_failure_removes_directory() -> std::io::Result<()> {
        #[expect(clippy::print_stderr)]
        let Some(smb_fs) = std::env::var(uv_static::EnvVars::UV_INTERNAL__TEST_SMB_FS).ok() else {
            eprintln!("Skipping: UV_INTERNAL__TEST_SMB_FS not set");
            return Ok(());
        };
        fs_err::create_dir_all(&smb_fs)?;
        let alt_tempdir = tempfile::tempdir_in(smb_fs)?;
        let tempdir = tempfile::tempdir()?;
        let link = tempdir.path().join("link");
        let target = alt_tempdir.path().join("target");
        fs_err::create_dir(&target)?;

        let err = create_junction(&target, &link).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidFilename);
        assert!(matches!(
            fs_err::symlink_metadata(&link),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound
        ));
        Ok(())
    }
}

/// Create a symlink at `dst` pointing to `src` on Unix or copy `src` to `dst` on Windows
///
/// This does not replace an existing symlink or file at `dst`.
///
/// This does not fallback to copying on Unix.
///
/// This function should only be used for files. If targeting a directory, use [`replace_symlink`]
/// instead; it will use a junction on Windows, which is more performant.
pub fn symlink_or_copy_file(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        fs_err::copy(src.as_ref(), dst.as_ref())?;
    }
    #[cfg(unix)]
    {
        fs_err::os::unix::fs::symlink(src.as_ref(), dst.as_ref())?;
    }

    Ok(())
}

/// Return a [`NamedTempFile`] in the specified directory.
///
/// Sets the permissions of the temporary file to `0o666`, to match the non-temporary file default.
/// ([`NamedTempfile`] defaults to `0o600`.)
#[cfg(unix)]
pub fn tempfile_in(path: &Path) -> std::io::Result<NamedTempFile> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o666))
        .tempfile_in(path)
}

/// Return a [`NamedTempFile`] in the specified directory.
#[cfg(not(unix))]
pub fn tempfile_in(path: &Path) -> std::io::Result<NamedTempFile> {
    tempfile::Builder::new().tempfile_in(path)
}

/// Write `data` to `path` atomically using a temporary file and atomic rename.
#[cfg(feature = "tokio")]
pub async fn write_atomic(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> std::io::Result<()> {
    let temp_file = tempfile_in(
        path.as_ref()
            .parent()
            .expect("Write path must have a parent"),
    )?;
    fs_err::tokio::write(&temp_file, &data).await?;
    persist_with_retry(temp_file, path.as_ref()).await
}

/// Write `data` to `path` atomically using a temporary file and atomic rename.
pub fn write_atomic_sync(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> std::io::Result<()> {
    let temp_file = tempfile_in(
        path.as_ref()
            .parent()
            .expect("Write path must have a parent"),
    )?;
    fs_err::write(&temp_file, &data)?;
    persist_with_retry_sync(temp_file, path.as_ref())
}

/// Copy `from` to `to` atomically using a temporary file and atomic rename.
pub fn copy_atomic_sync(from: impl AsRef<Path>, to: impl AsRef<Path>) -> std::io::Result<()> {
    let temp_file = tempfile_in(to.as_ref().parent().expect("Write path must have a parent"))?;
    fs_err::copy(from.as_ref(), &temp_file)?;
    persist_with_retry_sync(temp_file, to.as_ref())
}

#[cfg(windows)]
fn backoff_file_move() -> backon::ExponentialBackoff {
    use backon::BackoffBuilder;
    // This amounts to 10 total seconds of trying the operation.
    // We retry 10 times, starting at 10*(2^0) milliseconds for the first retry, doubling with each
    // retry, so the last (10th) one will take about 10*(2^9) milliseconds ~= 5 seconds. All other
    // attempts combined should equal the length of the last attempt (because it's a sum of powers
    // of 2), so 10 seconds overall.
    backon::ExponentialBuilder::default()
        .with_min_delay(std::time::Duration::from_millis(10))
        .with_max_times(10)
        .build()
}

/// Whether an I/O error may resolve on its own if the operation is retried.
///
/// On Windows, antivirus software, the search indexer, or other processes can hold a transient
/// handle on a freshly written file, making operations such as renames, removals, or persists fail
/// with `ERROR_ACCESS_DENIED` (surfaced as [`std::io::ErrorKind::PermissionDenied`]),
/// `ERROR_SHARING_VIOLATION`, or `ERROR_LOCK_VIOLATION`.
///
/// The latter two have no dedicated [`std::io::ErrorKind`] and are only matched for errors that
/// carry a raw OS error, such as those returned by [`TempPath::persist`]. `fs_err`-wrapped errors
/// preserve the [`std::io::ErrorKind`] but erase the raw OS error, so for them only the
/// `ERROR_ACCESS_DENIED` arm can match.
#[cfg(windows)]
fn is_transient_fs_error(err: &std::io::Error) -> bool {
    use windows::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};

    err.kind() == std::io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(ERROR_SHARING_VIOLATION.0.cast_signed())
        || err.raw_os_error() == Some(ERROR_LOCK_VIOLATION.0.cast_signed())
}

/// Run a filesystem `operation`, retrying (on Windows) if it fails with a transient operating
/// system error.
///
/// Transient errors (see `is_transient_fs_error`) are most common for DLLs, and the common
/// suggestion is to retry the operation with some backoff, here `backoff_file_move`. Each retry
/// is logged with the operation description returned by `describe`, which is only invoked when a
/// retry occurs. On non-Windows platforms, the operation is run exactly once.
///
/// The final error is returned unchanged, so callers can still match on [`std::io::Error::kind`].
///
/// See: <https://github.com/astral-sh/uv/issues/1491>, <https://github.com/astral-sh/uv/issues/9531>,
/// <https://github.com/astral-sh/uv/issues/15968> & <https://github.com/astral-sh/uv/issues/17430>
#[cfg_attr(not(windows), expect(unused_variables))]
fn retry_transient_sync<T>(
    describe: impl Fn() -> String,
    operation: impl FnMut() -> Result<T, std::io::Error>,
) -> Result<T, std::io::Error> {
    #[cfg(windows)]
    {
        use backon::BlockingRetryable;

        operation
            .retry(backoff_file_move())
            .sleep(std::thread::sleep)
            .when(is_transient_fs_error)
            .notify(|err, _dur| {
                warn!("Retrying {} due to transient error: {}", describe(), err);
            })
            .call()
    }
    #[cfg(not(windows))]
    {
        let mut operation = operation;
        operation()
    }
}

/// Asynchronous counterpart to [`retry_transient_sync`].
#[cfg(feature = "tokio")]
#[cfg_attr(not(windows), expect(unused_variables))]
async fn retry_transient<T, Fut>(
    describe: impl Fn() -> String,
    operation: impl FnMut() -> Fut,
) -> Result<T, std::io::Error>
where
    Fut: std::future::Future<Output = Result<T, std::io::Error>>,
{
    #[cfg(windows)]
    {
        use backon::Retryable;

        operation
            .retry(backoff_file_move())
            .sleep(tokio::time::sleep)
            .when(is_transient_fs_error)
            .notify(|err, _dur| {
                warn!("Retrying {} due to transient error: {}", describe(), err);
            })
            .await
    }
    #[cfg(not(windows))]
    {
        let mut operation = operation;
        operation().await
    }
}

/// Rename a file, retrying (on Windows) if it fails due to transient operating system errors.
#[cfg(feature = "tokio")]
pub async fn rename_with_retry(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
) -> Result<(), std::io::Error> {
    let from = from.as_ref();
    let to = to.as_ref();

    retry_transient(
        || format!("rename from {} to {}", from.display(), to.display()),
        || fs_err::tokio::rename(from, to),
    )
    .await
}

/// Wrap an arbitrary operation on two files, e.g., copying, with retries (on Windows) on
/// transient operating system errors.
///
/// Unlike the other retry helpers, the returned error is wrapped with `operation_name` and both
/// paths for context, which discards the original [`std::io::ErrorKind`].
pub fn with_retry_sync(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    operation_name: &str,
    operation: impl Fn() -> Result<(), std::io::Error>,
) -> Result<(), std::io::Error> {
    let from = from.as_ref();
    let to = to.as_ref();

    retry_transient_sync(
        || {
            format!(
                "{operation_name} from {} to {}",
                from.display(),
                to.display()
            )
        },
        operation,
    )
    .map_err(|err| {
        std::io::Error::other(format!(
            "Failed {} {} to {}: {}",
            operation_name,
            from.display(),
            to.display(),
            err
        ))
    })
}

/// Like [`fs_err::remove_file`], but retries (on Windows) on transient operating-system errors such
/// as antivirus or indexer file locks.
pub fn remove_file_with_retry(path: impl AsRef<Path>) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    retry_transient_sync(
        || format!("removal of {}", path.display()),
        || fs_err::remove_file(path),
    )
}

/// Like [`fs_err::remove_dir`], but retries (on Windows) on transient operating-system errors such
/// as antivirus or indexer file locks.
pub fn remove_dir_with_retry(path: impl AsRef<Path>) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    retry_transient_sync(
        || format!("removal of {}", path.display()),
        || fs_err::remove_dir(path),
    )
}

/// Like [`fs_err::remove_dir_all`], but retries (on Windows) on transient operating-system errors
/// such as antivirus or indexer file locks.
pub fn remove_dir_all_with_retry(path: impl AsRef<Path>) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    retry_transient_sync(
        || format!("removal of {}", path.display()),
        || fs_err::remove_dir_all(path),
    )
}

/// Run a single persist attempt, giving the [`TempPath`] back to the caller through `temp_path`
/// on failure so that the next attempt can reuse it.
///
/// [`TempPath::persist`] consumes the path and only returns it inside the error, so a retried
/// closure cannot hold onto it directly; shuttling it through an [`Option`] keeps each attempt a
/// plain [`FnMut`] call. Unlike a bare rename, [`TempPath::persist`] also clears the
/// `FILE_ATTRIBUTE_TEMPORARY` flag on Windows and disarms the delete-on-drop guard on success.
fn try_persist(temp_path: &mut Option<TempPath>, to: &Path) -> Result<(), std::io::Error> {
    if let Some(path) = temp_path.take() {
        path.persist(to).map_err(|err| {
            // Put the temporary path back for the next attempt.
            *temp_path = Some(err.path);
            err.error
        })
    } else {
        // Unreachable in practice: attempts run serially, and only a success (which ends the
        // retry loop) leaves the option empty.
        Err(std::io::Error::other(format!(
            "Lost the temporary file while persisting to {}",
            to.display()
        )))
    }
}

/// Add the destination path to a persist error, preserving the [`std::io::ErrorKind`].
fn persist_error_with_context(err: &std::io::Error, to: &Path) -> std::io::Error {
    std::io::Error::new(
        err.kind(),
        format!(
            "Failed to persist temporary file to {}: {}",
            to.display(),
            err
        ),
    )
}

/// Persist a [`NamedTempFile`], retrying (on Windows) if it fails due to transient operating
/// system errors.
///
/// The file handle is closed before the first attempt, so it cannot contribute to sharing
/// violations on Windows. If every attempt fails, the temporary file is deleted on drop.
#[cfg(feature = "tokio")]
async fn persist_with_retry(
    from: NamedTempFile,
    to: impl AsRef<Path>,
) -> Result<(), std::io::Error> {
    let to = to.as_ref();
    let mut temp_path = Some(from.into_temp_path());

    // Persisting is synchronous, so each attempt runs eagerly when the operation closure is
    // called and only the backoff sleeps are asynchronous.
    retry_transient(
        || format!("persist of temporary file to {}", to.display()),
        || std::future::ready(try_persist(&mut temp_path, to)),
    )
    .await
    .map_err(|err| persist_error_with_context(&err, to))
}

/// Persist a [`NamedTempFile`], retrying (on Windows) if it fails due to transient operating
/// system errors.
///
/// This is a synchronous implementation of [`persist_with_retry`].
pub fn persist_with_retry_sync(
    from: NamedTempFile,
    to: impl AsRef<Path>,
) -> Result<(), std::io::Error> {
    let to = to.as_ref();
    let mut temp_path = Some(from.into_temp_path());

    retry_transient_sync(
        || format!("persist of temporary file to {}", to.display()),
        || try_persist(&mut temp_path, to),
    )
    .map_err(|err| persist_error_with_context(&err, to))
}

/// Iterate over the subdirectories of a directory.
///
/// If the directory does not exist, returns an empty iterator.
pub fn directories(
    path: impl AsRef<Path>,
) -> Result<impl Iterator<Item = PathBuf>, std::io::Error> {
    let entries = match path.as_ref().read_dir() {
        Ok(entries) => Some(entries),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    Ok(entries
        .into_iter()
        .flatten()
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(err) => {
                warn!("Failed to read entry: {err}");
                None
            }
        })
        .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_dir()))
        .map(|entry| entry.path()))
}

/// Iterate over the entries in a directory.
///
/// If the directory does not exist, returns an empty iterator.
pub fn entries(path: impl AsRef<Path>) -> Result<impl Iterator<Item = PathBuf>, std::io::Error> {
    let entries = match path.as_ref().read_dir() {
        Ok(entries) => Some(entries),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    Ok(entries
        .into_iter()
        .flatten()
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(err) => {
                warn!("Failed to read entry: {err}");
                None
            }
        })
        .map(|entry| entry.path()))
}

/// Iterate over the files in a directory.
///
/// If the directory does not exist, returns an empty iterator.
pub fn files(path: impl AsRef<Path>) -> Result<impl Iterator<Item = PathBuf>, std::io::Error> {
    let entries = match path.as_ref().read_dir() {
        Ok(entries) => Some(entries),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    Ok(entries
        .into_iter()
        .flatten()
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(err) => {
                warn!("Failed to read entry: {err}");
                None
            }
        })
        .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_file()))
        .map(|entry| entry.path()))
}

/// Returns `true` if a path is a temporary file or directory.
pub fn is_temporary(path: impl AsRef<Path>) -> bool {
    path.as_ref()
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".tmp"))
}

/// Checks if the grandparent directory of the given executable is the base
/// of a virtual environment.
///
/// The procedure described in PEP 405 includes checking both the parent and
/// grandparent directory of an executable, but in practice we've found this to
/// be unnecessary.
pub fn is_virtualenv_executable(executable: impl AsRef<Path>) -> bool {
    executable
        .as_ref()
        .parent()
        .and_then(Path::parent)
        .is_some_and(is_virtualenv_base)
}

/// Returns `true` if a path is the base path of a virtual environment,
/// indicated by the presence of a `pyvenv.cfg` file.
///
/// The procedure described in PEP 405 includes scanning `pyvenv.cfg`
/// for a `home` key, but in practice we've found this to be
/// unnecessary.
pub fn is_virtualenv_base(path: impl AsRef<Path>) -> bool {
    path.as_ref().join("pyvenv.cfg").is_file()
}

/// Whether the error is due to a lock being held.
fn is_known_already_locked_error(err: &std::fs::TryLockError) -> bool {
    match err {
        std::fs::TryLockError::WouldBlock => true,
        std::fs::TryLockError::Error(err) => {
            // On Windows, we've seen: Os { code: 33, kind: Uncategorized, message: "The process cannot access the file because another process has locked a portion of the file." }
            if cfg!(windows) && err.raw_os_error() == Some(33) {
                return true;
            }
            false
        }
    }
}

/// An asynchronous reader that reports progress as bytes are read.
#[cfg(feature = "tokio")]
pub struct ProgressReader<Reader: tokio::io::AsyncRead + Unpin, Callback: Fn(usize) + Unpin> {
    reader: Reader,
    callback: Callback,
}

#[cfg(feature = "tokio")]
impl<Reader: tokio::io::AsyncRead + Unpin, Callback: Fn(usize) + Unpin>
    ProgressReader<Reader, Callback>
{
    /// Create a new [`ProgressReader`] that wraps another reader.
    pub fn new(reader: Reader, callback: Callback) -> Self {
        Self { reader, callback }
    }
}

#[cfg(feature = "tokio")]
impl<Reader: tokio::io::AsyncRead + Unpin, Callback: Fn(usize) + Unpin> tokio::io::AsyncRead
    for ProgressReader<Reader, Callback>
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.as_mut().reader)
            .poll_read(cx, buf)
            .map_ok(|()| {
                (self.callback)(buf.filled().len());
            })
    }
}

/// Recursively copy a directory and its contents.
pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    fs_err::create_dir_all(&dst)?;
    for entry in fs_err::read_dir(src.as_ref())? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs_err::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// Perform a safe removal of a virtual environment.
///
/// Links at `location` are removed without following them.
pub fn remove_virtualenv(location: &Path) -> io::Result<()> {
    let file_type = fs_err::symlink_metadata(location)?.file_type();
    if file_type.is_symlink() {
        return remove_symlink(location);
    }

    // On Windows, if the current executable is in the directory, defer self-deletion since Windows
    // won't let you unlink a running executable.
    #[cfg(windows)]
    if let Ok(itself) = std::env::current_exe() {
        let target = std::path::absolute(location)?;
        if itself.starts_with(&target) {
            debug!("Detected self-delete of executable: {}", itself.display());
            self_replace::self_delete_outside_path(location)?;
        }
    }

    // We defer removal of the `pyvenv.cfg` until the end, so if we fail to remove the environment,
    // uv can still identify it as a Python virtual environment that can be deleted.
    for entry in fs_err::read_dir(location)? {
        let entry = entry?;
        let path = entry.path();
        if path == location.join("pyvenv.cfg") {
            continue;
        }
        if path.is_dir() {
            fs_err::remove_dir_all(&path)?;
        } else {
            fs_err::remove_file(&path)?;
        }
    }

    match fs_err::remove_file(location.join("pyvenv.cfg")) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    // Remove the virtual environment directory itself
    match fs_err::remove_dir_all(location) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        // If the virtual environment is a mounted file system, e.g., in a Docker container, we
        // cannot delete it — but that doesn't need to be a fatal error
        Err(err) if err.kind() == io::ErrorKind::ResourceBusy => {
            debug!(
                "Skipping removal of `{}` directory due to {err}",
                location.display(),
            );
        }
        Err(err) => return Err(err),
    }

    Ok(())
}

/// Prepare an empty virtual environment directory, resolving links when possible.
///
/// Returns whether an existing entry was found.
pub fn clear_virtualenv(location: &Path) -> io::Result<bool> {
    let location = location
        .canonicalize()
        .unwrap_or_else(|_| location.to_path_buf());
    let cleared = match remove_virtualenv(&location) {
        Ok(()) => true,
        Err(err) if err.kind() == io::ErrorKind::NotFound => false,
        Err(err) => return Err(err),
    };
    fs_err::create_dir_all(location)?;
    Ok(cleared)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn remove_symlink_removes_directory_link_without_removing_target() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("target");
        fs_err::create_dir(&target)?;
        fs_err::write(target.join("file"), "content")?;
        let link = tempdir.path().join("link");

        create_symlink(&target, &link)?;
        remove_symlink(&link)?;

        assert!(matches!(
            fs_err::symlink_metadata(&link),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        assert_eq!(fs_err::read_to_string(target.join("file"))?, "content");
        Ok(())
    }

    #[test]
    fn remove_virtualenv_removes_directory_link_without_removing_target() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("target");
        fs_err::create_dir(&target)?;
        let marker = target.join("marker");
        fs_err::write(&marker, "")?;
        let environment = tempdir.path().join("environment");
        create_symlink(&target, &environment)?;

        remove_virtualenv(&environment)?;

        assert!(matches!(
            fs_err::symlink_metadata(environment),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        assert!(marker.is_file());
        Ok(())
    }

    #[test]
    fn clear_virtualenv_recreates_missing_directory() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let environment = tempdir.path().join("environment");

        assert!(!clear_virtualenv(&environment)?);
        assert!(environment.is_dir());
        Ok(())
    }

    #[test]
    fn remove_dir_all_with_retry_removes_populated_tree() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let dir = tempdir.path().join("pkg.data");
        fs_err::create_dir(&dir)?;
        fs_err::write(dir.join("file"), "content")?;
        fs_err::create_dir(dir.join("nested"))?;
        fs_err::write(dir.join("nested").join("file"), "content")?;

        remove_dir_all_with_retry(&dir)?;

        assert!(matches!(
            fs_err::symlink_metadata(&dir),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[test]
    fn remove_file_with_retry_removes_file() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let file = tempdir.path().join("file");
        fs_err::write(&file, "content")?;

        remove_file_with_retry(&file)?;

        assert!(matches!(
            fs_err::symlink_metadata(&file),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[test]
    fn remove_file_with_retry_preserves_not_found_errors() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;

        assert!(matches!(
            remove_file_with_retry(tempdir.path().join("missing")),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    /// `uninstall_wheel` skips missing `__pycache__` directories by matching
    /// [`io::ErrorKind::NotFound`]; the retry wrapper must not wrap the error.
    #[test]
    fn remove_dir_all_with_retry_preserves_not_found_errors() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;

        assert!(matches!(
            remove_dir_all_with_retry(tempdir.path().join("missing")),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[test]
    fn remove_dir_with_retry_removes_empty_directory() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let directory = tempdir.path().join("directory");
        fs_err::create_dir(&directory)?;

        remove_dir_with_retry(&directory)?;

        assert!(matches!(
            fs_err::symlink_metadata(&directory),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[test]
    fn retry_transient_sync_returns_first_success() -> io::Result<()> {
        let attempts = Cell::new(0_u32);

        let value = retry_transient_sync(
            || String::from("test operation"),
            || {
                attempts.set(attempts.get() + 1);
                Ok(42)
            },
        )?;

        assert_eq!(value, 42);
        assert_eq!(attempts.get(), 1);
        Ok(())
    }

    #[test]
    fn retry_transient_sync_does_not_retry_non_transient_errors() {
        let attempts = Cell::new(0_u32);

        let result: Result<(), _> = retry_transient_sync(
            || String::from("test operation"),
            || {
                attempts.set(attempts.get() + 1);
                Err(io::Error::from(io::ErrorKind::NotFound))
            },
        );

        assert_eq!(attempts.get(), 1);
        assert!(matches!(result, Err(err) if err.kind() == io::ErrorKind::NotFound));
    }

    /// The retry loop only exists on Windows; other platforms run the operation exactly once,
    /// even for errors that would be considered transient on Windows.
    #[cfg(not(windows))]
    #[test]
    fn retry_transient_sync_does_not_retry_off_windows() {
        let attempts = Cell::new(0_u32);

        let result: Result<(), _> = retry_transient_sync(
            || String::from("test operation"),
            || {
                attempts.set(attempts.get() + 1);
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            },
        );

        assert_eq!(attempts.get(), 1);
        assert!(matches!(result, Err(err) if err.kind() == io::ErrorKind::PermissionDenied));
    }

    #[cfg(windows)]
    #[test]
    fn retry_transient_sync_retries_transient_errors_until_success() -> io::Result<()> {
        let attempts = Cell::new(0_u32);

        retry_transient_sync(
            || String::from("test operation"),
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() < 3 {
                    Err(io::Error::from(io::ErrorKind::PermissionDenied))
                } else {
                    Ok(())
                }
            },
        )?;

        assert_eq!(attempts.get(), 3);
        Ok(())
    }

    /// Sharing violations have no dedicated [`io::ErrorKind`] and are retried based on the raw
    /// OS error, which is only carried by bare operating system errors such as those returned by
    /// [`TempPath::persist`].
    #[cfg(windows)]
    #[test]
    fn retry_transient_sync_retries_sharing_violations_until_success() -> io::Result<()> {
        use windows::Win32::Foundation::ERROR_SHARING_VIOLATION;

        let attempts = Cell::new(0_u32);

        retry_transient_sync(
            || String::from("test operation"),
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() < 3 {
                    Err(io::Error::from_raw_os_error(
                        ERROR_SHARING_VIOLATION.0.cast_signed(),
                    ))
                } else {
                    Ok(())
                }
            },
        )?;

        assert_eq!(attempts.get(), 3);
        Ok(())
    }

    /// [`fs_err`] wraps operating system errors as `io::Error::new(source.kind(), ..)`, which
    /// preserves the [`io::ErrorKind`] but erases the raw OS error. The predicate therefore
    /// matches wrapped access-denied errors by kind, while wrapped sharing violations (which have
    /// no dedicated kind) are known not to match.
    #[cfg(windows)]
    #[test]
    fn is_transient_fs_error_matches_bare_and_kind_preserving_errors() {
        use windows::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
        };

        // Bare OS errors carry the raw OS error, e.g., from `TempPath::persist`.
        for code in [
            ERROR_ACCESS_DENIED.0.cast_signed(),
            ERROR_SHARING_VIOLATION.0.cast_signed(),
            ERROR_LOCK_VIOLATION.0.cast_signed(),
        ] {
            assert!(is_transient_fs_error(&io::Error::from_raw_os_error(code)));
        }
        assert!(!is_transient_fs_error(&io::Error::from(
            io::ErrorKind::NotFound
        )));

        // `fs_err`-style wrapping: the kind survives, the raw OS error does not.
        let wrap = |code: i32| {
            let inner = io::Error::from_raw_os_error(code);
            io::Error::new(inner.kind(), inner)
        };
        assert!(is_transient_fs_error(&wrap(
            ERROR_ACCESS_DENIED.0.cast_signed()
        )));
        assert!(!is_transient_fs_error(&wrap(
            ERROR_SHARING_VIOLATION.0.cast_signed()
        )));
    }

    #[test]
    fn with_retry_sync_returns_success() -> io::Result<()> {
        with_retry_sync("source.txt", "target.txt", "copying", || Ok(()))
    }

    /// The wrap adds context but collapses the [`io::ErrorKind`] to [`io::ErrorKind::Other`];
    /// callers must not match on the kind.
    #[test]
    fn with_retry_sync_wraps_the_error_with_context() {
        let result = with_retry_sync("source.txt", "target.txt", "copying", || {
            Err(io::Error::from(io::ErrorKind::NotFound))
        });

        assert!(matches!(
            result,
            Err(err) if err.kind() == io::ErrorKind::Other
                && err.to_string().starts_with("Failed copying source.txt to target.txt:")
        ));
    }

    #[test]
    fn persist_with_retry_sync_moves_the_temporary_file() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("target");

        let temp_file = tempfile_in(tempdir.path())?;
        fs_err::write(&temp_file, "content")?;
        let temp_file_path = temp_file.path().to_path_buf();

        persist_with_retry_sync(temp_file, &target)?;

        assert_eq!(fs_err::read_to_string(&target)?, "content");
        assert!(matches!(
            fs_err::symlink_metadata(&temp_file_path),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[test]
    fn persist_with_retry_sync_replaces_an_existing_file() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("target");
        fs_err::write(&target, "old")?;

        let temp_file = tempfile_in(tempdir.path())?;
        fs_err::write(&temp_file, "new")?;

        persist_with_retry_sync(temp_file, &target)?;

        assert_eq!(fs_err::read_to_string(&target)?, "new");
        Ok(())
    }

    /// A failed persist deletes the temporary file, returns an error with context, and preserves
    /// the underlying [`io::ErrorKind`].
    #[test]
    fn persist_with_retry_sync_cleans_up_on_failure() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("nonexistent").join("target");

        let temp_file = tempfile_in(tempdir.path())?;
        let temp_file_path = temp_file.path().to_path_buf();

        assert!(matches!(
            persist_with_retry_sync(temp_file, &target),
            Err(err) if err.kind() == io::ErrorKind::NotFound
                && err.to_string().starts_with("Failed to persist temporary file to")
        ));
        assert!(matches!(
            fs_err::symlink_metadata(&temp_file_path),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[test]
    fn write_atomic_sync_replaces_an_existing_file() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("target");
        fs_err::write(&target, "old")?;

        write_atomic_sync(&target, "new")?;

        assert_eq!(fs_err::read_to_string(&target)?, "new");
        Ok(())
    }

    #[test]
    fn copy_atomic_sync_copies_the_source_file() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let source = tempdir.path().join("source");
        let target = tempdir.path().join("target");
        fs_err::write(&source, "content")?;

        copy_atomic_sync(&source, &target)?;

        assert_eq!(fs_err::read_to_string(&target)?, "content");
        assert_eq!(fs_err::read_to_string(&source)?, "content");
        Ok(())
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn retry_transient_returns_first_success() -> io::Result<()> {
        let attempts = Cell::new(0_u32);

        let value = retry_transient(
            || String::from("test operation"),
            || {
                attempts.set(attempts.get() + 1);
                std::future::ready(Ok(42))
            },
        )
        .await?;

        assert_eq!(value, 42);
        assert_eq!(attempts.get(), 1);
        Ok(())
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn retry_transient_does_not_retry_non_transient_errors() {
        let attempts = Cell::new(0_u32);

        let result: Result<(), _> = retry_transient(
            || String::from("test operation"),
            || {
                attempts.set(attempts.get() + 1);
                std::future::ready(Err(io::Error::from(io::ErrorKind::NotFound)))
            },
        )
        .await;

        assert_eq!(attempts.get(), 1);
        assert!(matches!(result, Err(err) if err.kind() == io::ErrorKind::NotFound));
    }

    #[cfg(all(windows, feature = "tokio"))]
    #[tokio::test]
    async fn retry_transient_retries_transient_errors_until_success() -> io::Result<()> {
        let attempts = Cell::new(0_u32);

        retry_transient(
            || String::from("test operation"),
            || {
                attempts.set(attempts.get() + 1);
                std::future::ready(if attempts.get() < 3 {
                    Err(io::Error::from(io::ErrorKind::PermissionDenied))
                } else {
                    Ok(())
                })
            },
        )
        .await?;

        assert_eq!(attempts.get(), 3);
        Ok(())
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn rename_with_retry_renames_a_file() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let source = tempdir.path().join("source");
        let target = tempdir.path().join("target");
        fs_err::write(&source, "content")?;

        rename_with_retry(&source, &target).await?;

        assert_eq!(fs_err::read_to_string(&target)?, "content");
        assert!(matches!(
            fs_err::symlink_metadata(&source),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn rename_with_retry_preserves_not_found_errors() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;

        let result = rename_with_retry(
            tempdir.path().join("missing"),
            tempdir.path().join("target"),
        )
        .await;

        assert!(matches!(result, Err(err) if err.kind() == io::ErrorKind::NotFound));
        Ok(())
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn persist_with_retry_replaces_an_existing_file() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("target");
        fs_err::write(&target, "old")?;

        let temp_file = tempfile_in(tempdir.path())?;
        fs_err::write(&temp_file, "new")?;
        let temp_file_path = temp_file.path().to_path_buf();

        persist_with_retry(temp_file, &target).await?;

        assert_eq!(fs_err::read_to_string(&target)?, "new");
        assert!(matches!(
            fs_err::symlink_metadata(&temp_file_path),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    /// Async counterpart to [`persist_with_retry_sync_cleans_up_on_failure`].
    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn persist_with_retry_cleans_up_on_failure() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("nonexistent").join("target");

        let temp_file = tempfile_in(tempdir.path())?;
        let temp_file_path = temp_file.path().to_path_buf();

        assert!(matches!(
            persist_with_retry(temp_file, &target).await,
            Err(err) if err.kind() == io::ErrorKind::NotFound
                && err.to_string().starts_with("Failed to persist temporary file to")
        ));
        assert!(matches!(
            fs_err::symlink_metadata(&temp_file_path),
            Err(err) if err.kind() == io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn write_atomic_replaces_an_existing_file() -> io::Result<()> {
        let tempdir = tempfile::tempdir()?;
        let target = tempdir.path().join("target");
        fs_err::write(&target, "old")?;

        write_atomic(&target, "new").await?;

        assert_eq!(fs_err::read_to_string(&target)?, "new");
        Ok(())
    }
}
