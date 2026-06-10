import { Directory, FileNode } from './types';

export function isDirectory(item: FileNode): item is Directory {
  return 'children' in item;
}

export function isDirectoryWithChildren(
  item: FileNode
): item is Required<Directory> {
  return isDirectory(item) && 'children' in item;
}

export function getAllFilePaths(item: FileNode, nodePath: string): string[] {
  if (!isDirectory(item)) {
    return [nodePath];
  }
  return (item.children ?? []).flatMap((child) =>
    getAllFilePaths(child, `${nodePath}/${child.name}`)
  );
}

export function getFolderState(
  item: Directory,
  selected: Set<string>,
  nodePath: string
): 'checked' | 'indeterminate' | 'unchecked' {
  const filePaths = getAllFilePaths(item, nodePath);
  if (filePaths.length === 0) return 'unchecked';
  const selectedCount = filePaths.filter((p) => selected.has(p)).length;
  if (selectedCount === filePaths.length) return 'checked';
  if (selectedCount > 0) return 'indeterminate';
  return 'unchecked';
}

export function filterToPattern(text: string): string {
  const t = text.trim();
  if (/[*?]/.test(t)) return t;
  return `*${t}*`;
}
