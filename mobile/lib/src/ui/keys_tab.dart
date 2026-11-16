import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../app_state.dart';
import '../kw_ffi.dart';
import '../models.dart';
import 'common.dart';
import 'theme.dart';

class KeysTab extends StatefulWidget {
  const KeysTab({
    super.key,
    required this.state,
    required this.onOpenSync,
    this.onOpenTerminal,
  });

  final AppState state;
  final VoidCallback onOpenSync;
  final VoidCallback? onOpenTerminal;

  @override
  State<KeysTab> createState() => _KeysTabState();
}

class _KeysTabState extends State<KeysTab> {
  String? _hostId;
  final TextEditingController _search = TextEditingController();

  AppState get state => widget.state;
  Bootstrap? get bootstrap => state.bootstrap;

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  static List<String> _extractTags(HostConfig h) {
    final tags = <String>[];
    final ip = h.host.trim();
    if (ip.startsWith('192.168.') ||
        ip.startsWith('10.') ||
        ip.startsWith('127.') ||
        ip.startsWith('172.16.') ||
        ip.startsWith('172.17.') ||
        ip.startsWith('172.18.') ||
        ip.startsWith('172.19.') ||
        ip.startsWith('172.2') ||
        ip.startsWith('172.30.') ||
        ip.startsWith('172.31.')) {
      tags.add('局域网');
    }
    final lower = '${h.name} ${h.host}'.toLowerCase();
    if (lower.contains('fnos') || lower.contains('nas') || lower.contains('存储')) {
      tags.add('NAS');
    }
    if (lower.contains('singapore') || lower.contains('sg') || lower.contains('新加坡')) {
      tags.add('新加坡');
    } else if (lower.contains('hongkong') || lower.contains('hk') || lower.contains('香港')) {
      tags.add('香港');
    } else if (lower.contains('japan') || lower.contains('jp') || lower.contains('tokyo') || lower.contains('日本')) {
      tags.add('日本');
    } else if (lower.contains('us') || lower.contains('usa') || lower.contains('america') || lower.contains('美国')) {
      tags.add('美国');
    }
    return tags;
  }

  HostConfig? get _selectedHost {
    final hosts = bootstrap?.hosts ?? <HostConfig>[];
    if (hosts.isEmpty) return null;
    final activeId = state.session?.host['id']?.toString() ?? '';
    if (activeId.isNotEmpty) {
      for (final h in hosts) {
        if (h.id == activeId) return h;
      }
    }
    if (_hostId != null) {
      for (final h in hosts) {
        if (h.id == _hostId) return h;
      }
    }
    return hosts.first;
  }

  @override
  Widget build(BuildContext context) {
    final host = _selectedHost;
    final session = state.session;
    return Column(
      children: [
        _header(host),
        Expanded(
          child: session == null ? _disconnected(host) : _connected(session),
        ),
      ],
    );
  }

  /* ------------------------------------------------------------------ */
  /* 顶部：主机与操作                                                     */
  /* ------------------------------------------------------------------ */

  Widget _header(HostConfig? host) {
    final hosts = bootstrap?.hosts ?? <HostConfig>[];
    final connected = state.connected;
    return Container(
      padding: EdgeInsets.fromLTRB(14, 10, 14, 10),
      decoration: BoxDecoration(
        color: KwColors.panel,
        border: Border(bottom: BorderSide(color: KwColors.border)),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                  color: connected ? KwColors.ok : KwColors.faint,
                  shape: BoxShape.circle,
                ),
              ),
              SizedBox(width: 8),
              Expanded(
                child: hosts.isEmpty
                    ? Text(
                        '还没有主机',
                        style: TextStyle(fontSize: 13, color: KwColors.dim),
                      )
                    : DropdownButtonHideUnderline(
                        child: DropdownButton<String>(
                          isExpanded: true,
                          value: host?.id,
                          dropdownColor: KwColors.bgElev,
                          borderRadius: BorderRadius.circular(10),
                          style: TextStyle(
                            fontSize: 13,
                            color: KwColors.text,
                            fontWeight: FontWeight.w600,
                            fontFamily: 'monospace',
                          ),
                          items: hosts
                              .map(
                                (h) => DropdownMenuItem(
                                  value: h.id,
                                  child: Text(
                                    '${h.label}  ·  ${h.endpoint}',
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ),
                              )
                              .toList(),
                          onChanged: connected
                              ? null
                              : (v) => setState(() => _hostId = v),
                        ),
                      ),
              ),
              IconButton(
                tooltip: '管理主机',
                onPressed: _manageHosts,
                icon: Icon(Icons.dns_outlined, size: 19),
                color: KwColors.dim,
              ),
            ],
          ),
          SizedBox(height: 8),
          Row(
            children: connected
                ? [
                    _action(Icons.refresh_rounded, '刷新', _refresh),
                    _action(Icons.add_rounded, '新增密钥', _addKey, primary: true),
                    if (widget.onOpenTerminal != null)
                      _action(
                        Icons.terminal_rounded,
                        '终端',
                        widget.onOpenTerminal!,
                      ),
                    _action(Icons.history_rounded, '备份', _openBackups),
                    _action(
                      Icons.link_off_rounded,
                      '断开',
                      _disconnect,
                      danger: true,
                    ),
                  ]
                : [
                    _action(
                      Icons.link_rounded,
                      '连接',
                      () => _connect(host),
                      primary: true,
                    ),
                    _action(Icons.add_rounded, '添加主机', _addHost),
                    if (hosts.isEmpty)
                      _action(
                        Icons.cloud_sync_rounded,
                        '云同步',
                        widget.onOpenSync,
                      ),
                  ],
          ),
        ],
      ),
    );
  }

  Widget _action(
    IconData icon,
    String label,
    VoidCallback onTap, {
    bool primary = false,
    bool danger = false,
  }) {
    final color = danger
        ? KwColors.danger
        : primary
        ? KwColors.accent
        : KwColors.dim;
    return Padding(
      padding: EdgeInsets.only(right: 6),
      child: Material(
        color: primary ? KwColors.accentSoft : Colors.transparent,
        borderRadius: BorderRadius.circular(7),
        child: InkWell(
          onTap: state.busy ? null : onTap,
          borderRadius: BorderRadius.circular(7),
          child: Container(
            height: 30,
            padding: EdgeInsets.symmetric(horizontal: 9),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(7),
              border: Border.all(
                color: primary
                    ? KwColors.accent.withValues(alpha: 0.55)
                    : KwColors.border,
              ),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, size: 14, color: color),
                SizedBox(width: 5),
                Text(label, style: TextStyle(fontSize: 12, color: color)),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /* ------------------------------------------------------------------ */
  /* 未连接（Termius 风格主机保险库列表）                               */
  /* ------------------------------------------------------------------ */

  Widget _disconnected(HostConfig? host) {
    final hosts = bootstrap?.hosts ?? <HostConfig>[];
    final q = _search.text.trim().toLowerCase();
    final filteredHosts = q.isEmpty
        ? hosts
        : hosts
            .where(
              (h) =>
                  h.label.toLowerCase().contains(q) ||
                  h.host.toLowerCase().contains(q) ||
                  h.username.toLowerCase().contains(q),
            )
            .toList();

    return ListView(
      padding: const EdgeInsets.all(14),
      children: [
        if (hosts.isEmpty)
          panel(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '先添加一台服务器',
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                    color: KwColors.text,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  '手机端不读 ~/.ssh/config。可以手填主机，或在「密钥包·同步」登录微软账号，把桌面端的密钥库拉下来。',
                  style: TextStyle(
                    fontSize: 12,
                    height: 1.6,
                    color: KwColors.dim,
                  ),
                ),
                const SizedBox(height: 14),
                Row(
                  children: [
                    FilledButton.icon(
                      onPressed: _addHost,
                      icon: const Icon(Icons.add_rounded, size: 16),
                      label: const Text('添加主机', style: TextStyle(fontSize: 13)),
                    ),
                    const SizedBox(width: 10),
                    OutlinedButton.icon(
                      onPressed: widget.onOpenSync,
                      icon: const Icon(Icons.cloud_sync_rounded, size: 16),
                      label: const Text('云同步', style: TextStyle(fontSize: 13)),
                    ),
                  ],
                ),
              ],
            ),
          )
        else ...[
          // 搜索框
          Container(
            height: 38,
            margin: const EdgeInsets.only(bottom: 12),
            child: TextField(
              controller: _search,
              style: TextStyle(fontSize: 13, color: KwColors.text),
              decoration: InputDecoration(
                hintText: '筛选主机名称、IP 或用户名...',
                hintStyle: TextStyle(fontSize: 12, color: KwColors.faint),
                prefixIcon:
                    Icon(Icons.search_rounded, size: 17, color: KwColors.dim),
                suffixIcon: _search.text.isNotEmpty
                    ? IconButton(
                        icon: Icon(
                          Icons.close_rounded,
                          size: 16,
                          color: KwColors.dim,
                        ),
                        onPressed: () => setState(() => _search.clear()),
                      )
                    : null,
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 0),
                isDense: true,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: KwColors.border),
                ),
              ),
              onChanged: (_) => setState(() {}),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Row(
              children: [
                Text(
                  '服务器保险库 (${filteredHosts.length}${q.isNotEmpty ? ' / ${hosts.length}' : ''})',
                  style: TextStyle(
                    fontSize: 11.5,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.4,
                    color: KwColors.dim,
                  ),
                ),
                const Spacer(),
                InkWell(
                  onTap: _addHost,
                  borderRadius: BorderRadius.circular(6),
                  child: Padding(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    child: Text(
                      '+ 添加主机',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: KwColors.accent,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
          if (filteredHosts.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 24),
              child: Center(
                child: Text(
                  '未找到匹配的主机',
                  style: TextStyle(fontSize: 12.5, color: KwColors.faint),
                ),
              ),
            )
          else
            ...filteredHosts.map(
              (h) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _hostVaultCard(h, isSelected: h.id == host?.id),
              ),
            ),
        ],
        const SizedBox(height: 6),
        panel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                '连接后能做什么',
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: KwColors.text,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                '查看 / 搜索 / 备注服务器上的每把钥匙，生成并追加新钥匙，三步式更换，'
                '多选删除，备份差异与恢复，以及切换「仅密钥登录」。'
                '所有写操作都会先备份、再原子写入、最后回读校验。',
                style: TextStyle(
                  fontSize: 12,
                  height: 1.6,
                  color: KwColors.dim,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _hostVaultCard(HostConfig h, {bool isSelected = false}) {
    final hasKey = h.identityFile.isNotEmpty;
    final keyBadge = hasKey
        ? h.identityFile.split(RegExp(r'[/\\]')).last
        : '密码登录';
    final isNas = h.label.toUpperCase().contains('FNOS') ||
        h.label.toUpperCase().contains('NAS') ||
        h.label.contains('存储');
    final tags = _extractTags(h);

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: KwColors.panel,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: isSelected
              ? KwColors.accent.withValues(alpha: 0.6)
              : KwColors.border,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              // 智能头像 + 在线指示灯
              Stack(
                clipBehavior: Clip.none,
                children: [
                  Container(
                    width: 38,
                    height: 38,
                    decoration: BoxDecoration(
                      color: KwColors.accentSoft,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                        color: KwColors.accent.withValues(alpha: 0.35),
                      ),
                    ),
                    alignment: Alignment.center,
                    child: isNas
                        ? Icon(
                            Icons.storage_rounded,
                            size: 19,
                            color: KwColors.accent,
                          )
                        : (h.label.isNotEmpty &&
                                RegExp(r'^[a-zA-Z0-9]').hasMatch(h.label))
                            ? Text(
                                h.label[0].toUpperCase(),
                                style: TextStyle(
                                  fontSize: 16,
                                  fontWeight: FontWeight.w700,
                                  color: KwColors.accent,
                                ),
                              )
                            : Icon(
                                Icons.dns_rounded,
                                size: 18,
                                color: KwColors.accent,
                              ),
                  ),
                  Positioned(
                    right: -1,
                    bottom: -1,
                    child: Container(
                      width: 9,
                      height: 9,
                      decoration: BoxDecoration(
                        color: KwColors.ok,
                        shape: BoxShape.circle,
                        border: Border.all(color: KwColors.panel, width: 1.5),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Flexible(
                          child: Text(
                            h.label,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 14.5,
                              fontWeight: FontWeight.w600,
                              color: KwColors.text,
                            ),
                          ),
                        ),
                        for (final tag in tags) ...[
                          const SizedBox(width: 5),
                          chip(
                            tag,
                            color: KwColors.accent,
                            background: KwColors.accentSoft,
                          ),
                        ],
                      ],
                    ),
                    const SizedBox(height: 3),
                    InkWell(
                      onTap: () {
                        HapticFeedback.lightImpact();
                        copyText(context, h.endpoint, '主机地址');
                      },
                      borderRadius: BorderRadius.circular(4),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(vertical: 1),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Flexible(
                              child: Text(
                                h.endpoint,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(
                                  fontSize: 11.5,
                                  fontFamily: 'monospace',
                                  color: KwColors.dim,
                                ),
                              ),
                            ),
                            const SizedBox(width: 4),
                            Icon(
                              Icons.copy_rounded,
                              size: 11,
                              color: KwColors.faint,
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              IconButton(
                tooltip: '编辑配置',
                visualDensity: VisualDensity.compact,
                padding: EdgeInsets.zero,
                constraints:
                    const BoxConstraints(minWidth: 30, minHeight: 30),
                icon:
                    Icon(Icons.edit_outlined, size: 16, color: KwColors.dim),
                onPressed: () => _showHostDialog(initial: h),
              ),
              PopupMenuButton<String>(
                icon: Icon(
                  Icons.more_vert_rounded,
                  size: 17,
                  color: KwColors.dim,
                ),
                color: KwColors.bgElev,
                padding: EdgeInsets.zero,
                constraints:
                    const BoxConstraints(minWidth: 28, minHeight: 28),
                onSelected: (v) async {
                  if (v == 'copy') {
                    copyText(context, h.endpoint, '主机地址');
                  } else if (v == 'edit') {
                    _showHostDialog(initial: h);
                  } else if (v == 'delete') {
                    final ok = await confirm(
                      context,
                      title: '删除主机',
                      message:
                          '确定要删除主机「${h.label}」吗？只删本机配置，不会动服务器钥匙。',
                      danger: true,
                      confirmText: '删除',
                    );
                    if (!ok) return;
                    try {
                      await state.deleteHost(h.id);
                    } catch (e) {
                      if (mounted) showError(context, e);
                    }
                  }
                },
                itemBuilder: (ctx) => [
                  const PopupMenuItem(
                    value: 'copy',
                    child: Row(
                      children: [
                        Icon(Icons.copy_rounded, size: 15),
                        SizedBox(width: 8),
                        Text('复制地址', style: TextStyle(fontSize: 12.5)),
                      ],
                    ),
                  ),
                  const PopupMenuItem(
                    value: 'edit',
                    child: Row(
                      children: [
                        Icon(Icons.edit_outlined, size: 15),
                        SizedBox(width: 8),
                        Text('编辑配置', style: TextStyle(fontSize: 12.5)),
                      ],
                    ),
                  ),
                  const PopupMenuItem(
                    value: 'delete',
                    child: Row(
                      children: [
                        Icon(Icons.delete_outline_rounded,
                            size: 15, color: Colors.redAccent),
                        SizedBox(width: 8),
                        Text('删除主机',
                            style: TextStyle(
                                fontSize: 12.5, color: Colors.redAccent)),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              // 认证与代理标识
              chip(
                hasKey ? '🔑 $keyBadge' : '🔒 密码',
                color: hasKey ? KwColors.ok : KwColors.dim,
                background: hasKey ? KwColors.okSoft : KwColors.surface3,
              ),
              if (h.hasProxy) ...[
                const SizedBox(width: 5),
                chip(
                  h.proxyKind.toUpperCase(),
                  color: KwColors.accent,
                  background: KwColors.accentSoft,
                ),
              ],
              const Spacer(),
              // 操作按钮组
              OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  minimumSize: const Size(0, 32),
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                  side: BorderSide(
                    color: KwColors.border,
                  ),
                ),
                onPressed: state.busy
                    ? null
                    : () {
                        setState(() => _hostId = h.id);
                        _connect(h);
                      },
                icon: Icon(Icons.vpn_key_outlined,
                    size: 14, color: KwColors.dim),
                label: Text(
                  '密钥',
                  style: TextStyle(fontSize: 12, color: KwColors.text),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.icon(
                style: FilledButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  minimumSize: const Size(0, 32),
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                ),
                onPressed: state.busy
                    ? null
                    : () {
                        setState(() => _hostId = h.id);
                        _connect(h, openTerminal: true);
                      },
                icon: const Icon(Icons.terminal_rounded, size: 14),
                label: const Text(
                  '>_ 终端',
                  style:
                      TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  /* ------------------------------------------------------------------ */
  /* 已连接                                                              */
  /* ------------------------------------------------------------------ */

  Widget _connected(SessionView session) {
    final keys = session.keys;
    return ListView(
      padding: EdgeInsets.all(14),
      children: [
        panel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      session.endpoint,
                      style: TextStyle(
                        fontSize: 13,
                        fontFamily: 'monospace',
                        color: KwColors.text,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  InkWell(
                    onTap: _openSshd,
                    borderRadius: BorderRadius.circular(20),
                    child: chip(
                      state.sshKeyOnly ? '仅密钥登录' : '密码也可登录',
                      color: state.sshKeyOnly ? KwColors.ok : KwColors.warn,
                      background: state.sshKeyOnly
                          ? KwColors.okSoft
                          : KwColors.warnSoft,
                    ),
                  ),
                ],
              ),
              SizedBox(height: 6),
              Text(
                [
                  if (session.serverUname.isNotEmpty) session.serverUname,
                  session.remotePath,
                  '${session.authMethod == 'key' ? '密钥登录' : '密码登录'} · '
                      '${session.totalKeys} 把钥匙',
                  if (session.malformed > 0)
                    '${session.malformed} 行无法识别（已原样保留）',
                ].join(' · '),
                style: TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: KwColors.faint,
                  height: 1.5,
                ),
              ),
            ],
          ),
        ),
        SizedBox(height: 10),
        if (keys.isEmpty)
          panel(
            child: Padding(
              padding: EdgeInsets.symmetric(vertical: 18),
              child: Center(
                child: Text(
                  session.fileExists
                      ? 'authorized_keys 里还没有公钥'
                      : 'authorized_keys 还不存在，新增一把就会创建',
                  style: TextStyle(fontSize: 12.5, color: KwColors.dim),
                ),
              ),
            ),
          )
        else
          ...keys.map(
            (k) => Padding(
              padding: EdgeInsets.only(bottom: 10),
              child: _keyCard(k, session),
            ),
          ),
      ],
    );
  }

  Widget _keyCard(KeyItem item, SessionView session) {
    final local = bootstrap?.privateKeyFor(item.fingerprint);
    final note = bootstrap?.keyNotes[item.fingerprint] ?? '';
    final isUsedKey = item.fingerprint == session.usedKeyFp;

    return Container(
      padding: EdgeInsets.all(13),
      decoration: BoxDecoration(
        color: KwColors.panel,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: isUsedKey
              ? KwColors.ok.withValues(alpha: 0.45)
              : KwColors.border,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              chip(item.type.isEmpty ? '未知类型' : item.type),
              if (isUsedKey) ...[
                SizedBox(width: 8),
                SizedBox(
                  width: 7,
                  height: 7,
                  child: DecoratedBox(
                    decoration: BoxDecoration(
                      color: KwColors.ok,
                      shape: BoxShape.circle,
                    ),
                  ),
                ),
                SizedBox(width: 4),
                Text(
                  '本次在用',
                  style: TextStyle(fontSize: 10.5, color: KwColors.ok),
                ),
              ],
              if (item.isDuplicate) ...[
                SizedBox(width: 6),
                chip('重复', color: KwColors.warn, background: KwColors.warnSoft),
              ],
              Spacer(),
              PopupMenuButton<String>(
                icon: Icon(
                  Icons.more_horiz_rounded,
                  size: 18,
                  color: KwColors.dim,
                ),
                color: KwColors.bgElev,
                onSelected: (v) {
                  if (v == 'note') {
                    _editNote(item);
                  } else if (v == 'replace') {
                    _replace(item);
                  } else if (v == 'delete') {
                    _delete(item);
                  } else {
                    copyText(context, item.fingerprint, 'SHA256 指纹');
                  }
                },
                itemBuilder: (_) => [
                  PopupMenuItem(value: 'copy', child: Text('复制指纹')),
                  PopupMenuItem(value: 'note', child: Text('编辑备注')),
                  PopupMenuItem(value: 'replace', child: Text('更换钥匙')),
                  PopupMenuItem(value: 'delete', child: Text('删除钥匙')),
                ],
              ),
            ],
          ),
          SizedBox(height: 4),
          Text(
            item.comment.isEmpty ? '(无注释)' : item.comment,
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w600,
              color: KwColors.text,
            ),
          ),
          SizedBox(height: 3),
          InkWell(
            onTap: () => copyText(context, item.fingerprint, 'SHA256 指纹'),
            child: Text(
              shortFp(item.fingerprint),
              style: TextStyle(
                fontSize: 11.5,
                fontFamily: 'monospace',
                color: KwColors.dim,
              ),
            ),
          ),
          if (item.options.isNotEmpty) ...[
            SizedBox(height: 4),
            Text(
              '选项：${item.options}',
              style: TextStyle(
                fontSize: 11,
                fontFamily: 'monospace',
                color: KwColors.warn,
                height: 1.4,
              ),
            ),
          ],
          SizedBox(height: 9),
          Row(
            children: [
              Icon(
                local != null ? Icons.check_circle_outline : Icons.help_outline,
                size: 13,
                color: local != null ? KwColors.ok : KwColors.faint,
              ),
              SizedBox(width: 4),
              Flexible(
                child: Text(
                  local != null ? local.name : '本机无匹配私钥',
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 11.5,
                    fontFamily: 'monospace',
                    color: local != null ? KwColors.ok : KwColors.faint,
                  ),
                ),
              ),
              if (note.isNotEmpty) ...[
                SizedBox(width: 8),
                Flexible(child: chip('备注: $note')),
              ],
            ],
          ),
        ],
      ),
    );
  }

  /* ------------------------------------------------------------------ */
  /* 主机弹窗                                                            */
  /* ------------------------------------------------------------------ */

  Future<void> _addHost() => _showHostDialog();

  Future<void> _showHostDialog({HostConfig? initial}) async {
    final isEdit = initial != null;
    final name = TextEditingController(text: initial?.name ?? '');
    final host = TextEditingController(text: initial?.host ?? '');
    final port = TextEditingController(text: (initial?.port ?? 22).toString());
    final user = TextEditingController(text: initial?.username ?? 'root');
    final remotePath = TextEditingController(text: initial?.remotePath ?? '');
    final keys = bootstrap?.privateKeys ?? <LocalKeyEntry>[];
    var identity = initial?.identityFile ?? '';
    var submitted = false;

    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: Text(isEdit ? '编辑服务器配置' : '添加服务器'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                field(name, '备注名称', hint: '例如：prod-vps、FNOS-8100T'),
                field(host, '主机地址 *', hint: 'IP 或域名，如 84.54.3.70'),
                field(port, '端口 *', keyboard: TextInputType.number),
                field(user, '登录用户 *', hint: 'root / ubuntu / admin'),
                if (keys.isNotEmpty) ...[
                  DropdownButtonFormField<String>(
                    initialValue: identity.isEmpty ? '' : identity,
                    decoration: InputDecoration(
                      labelText: '登录认证方式',
                      helperText: '来自手机随身密钥包；不选则用密码登录',
                      helperStyle: TextStyle(
                        fontSize: 11,
                        color: KwColors.faint,
                      ),
                    ),
                    dropdownColor: KwColors.bgElev,
                    items: [
                      const DropdownMenuItem(value: '', child: Text('🔒 密码登录')),
                      ...keys.map(
                        (k) => DropdownMenuItem(
                          value: k.path,
                          child: Text(
                            '🔑 ${k.name}',
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(
                              fontSize: 12,
                              fontFamily: 'monospace',
                            ),
                          ),
                        ),
                      ),
                    ],
                    onChanged: (v) => setLocal(() => identity = v ?? ''),
                  ),
                  const SizedBox(height: 12),
                ],
                field(
                  remotePath,
                  '远端 authorized_keys 路径（可选）',
                  hint: '留空默认 ~/.ssh/authorized_keys',
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('取消'),
            ),
            FilledButton(
              onPressed: () {
                submitted = true;
                Navigator.pop(ctx);
              },
              child: Text(isEdit ? '保存更改' : '添加'),
            ),
          ],
        ),
      ),
    );

    final data = (
      name: name.text.trim(),
      host: host.text.trim(),
      port: int.tryParse(port.text.trim()) ?? 22,
      user: user.text.trim(),
      remotePath: remotePath.text.trim(),
      identity: identity,
    );
    name.dispose();
    host.dispose();
    port.dispose();
    user.dispose();
    remotePath.dispose();

    if (!submitted || !mounted) return;
    if (data.host.isEmpty || data.user.isEmpty) {
      showSnack(context, '地址和用户名不能为空', danger: true);
      return;
    }
    try {
      await state.saveHost(
        id: initial?.id,
        name: data.name.isEmpty ? data.host : data.name,
        host: data.host,
        port: data.port,
        username: data.user,
        identityFile: data.identity,
        remotePath: data.remotePath,
        proxyKind: initial?.proxyKind ?? '',
        proxyHost: initial?.proxyHost ?? '',
        proxyPort: initial?.proxyPort ?? 1080,
      );
      if (mounted) {
        showSnack(context, isEdit ? '服务器配置已更新' : '服务器已添加', ok: true);
      }
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  Future<void> _manageHosts() async {
    final hosts = bootstrap?.hosts ?? <HostConfig>[];
    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: KwColors.bgElev,
      builder: (ctx) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          padding: const EdgeInsets.all(16),
          children: [
            Text(
              '主机管理',
              style: TextStyle(
                fontSize: 15,
                fontWeight: FontWeight.w600,
                color: KwColors.text,
              ),
            ),
            const SizedBox(height: 8),
            if (hosts.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 12),
                child: Text(
                  '还没有主机',
                  style: TextStyle(fontSize: 13, color: KwColors.dim),
                ),
              ),
            ...hosts.map(
              (h) => ListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(
                  h.label,
                  style: TextStyle(fontSize: 13, color: KwColors.text),
                ),
                subtitle: Text(
                  h.endpoint,
                  style: TextStyle(
                    fontSize: 11,
                    fontFamily: 'monospace',
                    color: KwColors.dim,
                  ),
                ),
                trailing: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    IconButton(
                      icon: Icon(
                        Icons.edit_outlined,
                        size: 18,
                        color: KwColors.dim,
                      ),
                      onPressed: () {
                        Navigator.pop(ctx);
                        _showHostDialog(initial: h);
                      },
                    ),
                    IconButton(
                      icon: Icon(
                        Icons.delete_outline_rounded,
                        size: 18,
                        color: KwColors.danger,
                      ),
                      onPressed: () async {
                        final ok = await confirm(
                          context,
                          title: '删除主机',
                          message: '只删本机配置，不会动服务器上的任何钥匙。',
                          danger: true,
                          confirmText: '删除',
                        );
                        if (!ok) return;
                        try {
                          await state.deleteHost(h.id);
                        } catch (e) {
                          if (mounted) showError(context, e);
                        }
                      },
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              onPressed: () {
                Navigator.pop(ctx);
                _addHost();
              },
              icon: const Icon(Icons.add_rounded, size: 16),
              label: const Text('添加主机'),
            ),
          ],
        ),
      ),
    );
  }

  /* ------------------------------------------------------------------ */
  /* 连接                                                                */
  /* ------------------------------------------------------------------ */

  Future<void> _connect(HostConfig? host, {bool openTerminal = false}) async {
    if (host == null) {
      showSnack(context, '先添加一台主机', danger: true);
      return;
    }
    final password = TextEditingController();
    final passphrase = TextEditingController();

    Future<void> attempt(String? trust) async {
      try {
        await state.connect(
          host,
          password: password.text,
          passphrase: passphrase.text,
          trustFingerprint: trust,
        );
        if (!mounted) return;
        Navigator.of(context).pop();
        showSnack(context, '已连接 ${host.endpoint}', ok: true);
        if (openTerminal) {
          widget.onOpenTerminal?.call();
        }
      } on KwException catch (e) {
        if (!mounted) return;
        if (e.isHostKeyUnknown || e.isHostKeyChanged) {
          final fp =
              e.details?['fingerprint']?.toString() ??
              e.details?['current']?.toString();
          final ok = await confirm(
            context,
            title: e.isHostKeyChanged ? '主机密钥已变化' : '首次连接，请核对指纹',
            message: '${e.message}\n\n指纹：${fp ?? '（未返回）'}',
            confirmText: '信任并连接',
            danger: e.isHostKeyChanged,
          );
          if (ok && fp != null && fp.isNotEmpty) await attempt(fp);
          return;
        }
        showError(context, e);
      } catch (e) {
        if (mounted) showError(context, e);
      }
    }

    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: Text('连接 ${host.label}'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                host.identityFile.isEmpty
                    ? '这台主机没有绑定私钥，需要密码登录。'
                    : '已绑定私钥：${host.identityFile}',
                style: TextStyle(fontSize: 12, color: KwColors.dim),
              ),
              SizedBox(height: 12),
              field(password, '登录密码（可选）', obscure: true),
              field(passphrase, '私钥 passphrase（可选）', obscure: true),
              Text(
                '密码与 passphrase 只在本次连接使用，不落盘、不写日志。',
                style: TextStyle(fontSize: 11, color: KwColors.faint),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: Text('取消')),
          FilledButton(onPressed: () => attempt(null), child: Text('连接')),
        ],
      ),
    );
    password.dispose();
    passphrase.dispose();
  }

  Future<void> _refresh() async {
    try {
      await state.refreshSession();
      if (mounted) showSnack(context, '已刷新', ok: true);
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  Future<void> _disconnect() async {
    final ok = await confirm(
      context,
      title: '断开连接',
      message: '断开后需要重新输入密码 / passphrase。',
      confirmText: '断开',
    );
    if (!ok) return;
    try {
      await state.disconnect();
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  /* ------------------------------------------------------------------ */
  /* 密钥操作                                                            */
  /* ------------------------------------------------------------------ */

  Future<void> _addKey() async {
    final comment = TextEditingController();
    final pass = TextEditingController();
    final pasted = TextEditingController();
    var mode = 'generate';
    var algorithm = 'ed25519';
    var switchToNew = false;

    final submitted = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: Text('新增密钥'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                SegmentedButton<String>(
                  segments: const [
                    ButtonSegment(value: 'generate', label: Text('生成新密钥')),
                    ButtonSegment(value: 'paste', label: Text('粘贴公钥')),
                  ],
                  selected: {mode},
                  onSelectionChanged: (v) => setLocal(() => mode = v.first),
                ),
                SizedBox(height: 16),
                if (mode == 'paste')
                  field(
                    pasted,
                    '公钥内容',
                    hint: 'ssh-ed25519 AAAA... 备注',
                    maxLines: 4,
                    helper: '电脑上同步过来的那把钥匙可以直接粘进来，不必重新生成',
                  )
                else ...[
                  DropdownButtonFormField<String>(
                    initialValue: algorithm,
                    decoration: InputDecoration(labelText: '算法'),
                    dropdownColor: KwColors.bgElev,
                    items: [
                      DropdownMenuItem(
                        value: 'ed25519',
                        child: Text('Ed25519（推荐）'),
                      ),
                      DropdownMenuItem(value: 'rsa', child: Text('RSA 3072')),
                    ],
                    onChanged: (v) => setLocal(() => algorithm = v ?? 'ed25519'),
                  ),
                  SizedBox(height: 12),
                  field(comment, '注释', hint: 'mobile@phone'),
                  field(pass, 'passphrase（可选）', obscure: true),
                ],
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: switchToNew,
                  onChanged: (v) => setLocal(() => switchToNew = v ?? false),
                  title: Text(
                    '顺便把本机登录密钥切成新的',
                    style: TextStyle(fontSize: 13, color: KwColors.text),
                  ),
                  subtitle: Text(
                    '会先用新私钥真实登录一次，验证通过才改配置',
                    style: TextStyle(fontSize: 11, color: KwColors.faint),
                  ),
                  dense: true,
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: Text('取消'),
            ),
            FilledButton(
              onPressed: () {
                if (mode == 'paste' && pasted.text.trim().isEmpty) return;
                Navigator.pop(ctx, true);
              },
              child: Text(mode == 'paste' ? '写入服务器' : '生成并写入'),
            ),
          ],
        ),
      ),
    );
    final c = comment.text;
    final p = pass.text;
    final pastedText = pasted.text.trim();
    comment.dispose();
    pass.dispose();
    pasted.dispose();
    if (submitted != true || !mounted) return;

    try {
      final data = await state.addKey(
        mode: mode,
        algorithm: algorithm,
        comment: c,
        passphrase: p.isEmpty ? null : p,
        publicKey: pastedText,
        switchToNew: switchToNew,
      );
      if (mounted) _showSteps('新增密钥', data);
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  Future<void> _replace(KeyItem item) async {
    final ok = await confirm(
      context,
      title: '三步式更换密钥',
      message:
          '替换「${item.comment.isEmpty ? shortFp(item.fingerprint) : item.comment}」：\n'
          '1. 先写入新钥匙\n2. 用新私钥真实登录一次\n3. 验证通过才删除旧钥匙\n\n'
          '新钥匙生成在手机密钥包里，默认不加密。',
      confirmText: '开始更换',
    );
    if (!ok || !mounted) return;

    try {
      var data = await state.replaceKey(oldFingerprint: item.fingerprint);
      if (data['needsForce'] == true && mounted) {
        final force = await confirm(
          context,
          title: '新钥匙未能自动验证',
          message:
              '${data['message'] ?? '新私钥登录测试未通过'}\n\n'
              '新钥匙已经写入服务器，旧钥匙还没有删除。确认新钥匙能登录后，'
              '可以强制删掉旧钥匙；不会重复生成第三把。',
          confirmText: '删除旧钥匙',
          danger: true,
        );
        if (!force) {
          if (mounted) _showSteps('更换密钥', data);
          return;
        }
        // replace_key 每次调用都会重新生成一把新钥匙；这里只补删旧钥匙，
        // 避免 force 重试时又追加一把
        data = await state.deleteKeys([item.fingerprint], force: true);
      }
      if (mounted) _showSteps('更换密钥', data);
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  Future<void> _delete(KeyItem item) async {
    final session = state.session;
    final isUsed = session != null && item.fingerprint == session.usedKeyFp;
    final ok = await confirm(
      context,
      title: '删除密钥',
      message: isUsed
          ? '这把是【本次连接正在使用】的钥匙，删掉会立刻把你锁在门外。\n\n'
                '写入前会自动备份原文件，但仍需二次确认。'
          : '从服务器删除「${item.comment.isEmpty ? shortFp(item.fingerprint) : item.comment}」？\n'
                '写入前会自动备份原文件。',
      confirmText: isUsed ? '仍然删除' : '删除',
      danger: true,
    );
    if (!ok || !mounted) return;

    try {
      var data = await state.deleteKeys([item.fingerprint]);
      if (data['needsForce'] == true && mounted) {
        final force = await confirm(
          context,
          title: '需要强制确认',
          message: data['message']?.toString() ?? '这把钥匙正在使用中。',
          confirmText: '强制删除',
          danger: true,
        );
        if (!force) return;
        data = await state.deleteKeys([item.fingerprint], force: true);
      }
      if (mounted) {
        final steps = data['steps'];
        showSnack(
          context,
          steps is List && steps.isNotEmpty ? steps.last.toString() : '删除完成',
          ok: true,
        );
      }
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  Future<void> _editNote(KeyItem item) async {
    final controller = TextEditingController(
      text: bootstrap?.keyNotes[item.fingerprint] ?? '',
    );
    final saved = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('钥匙备注'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              '只存本机，不写服务器；最多 200 字。留空即删除备注。',
              style: TextStyle(fontSize: 12, color: KwColors.dim),
            ),
            SizedBox(height: 12),
            field(controller, '备注', hint: '谁的电脑 / 用途'),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text('保存'),
          ),
        ],
      ),
    );
    final note = controller.text.trim();
    controller.dispose();
    if (saved != true || !mounted) return;
    try {
      await state.setNote(item.fingerprint, note);
      if (mounted) showSnack(context, '备注已保存', ok: true);
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  void _showSteps(String title, Map<String, dynamic> data) {
    final steps = data['steps'];
    final message = data['message']?.toString() ?? '';
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (message.isNotEmpty) ...[
                Text(
                  message,
                  style: TextStyle(
                    fontSize: 12.5,
                    color: KwColors.warn,
                    height: 1.5,
                  ),
                ),
                SizedBox(height: 10),
              ],
              if (steps is List)
                ...steps.map(
                  (s) => Padding(
                    padding: EdgeInsets.only(bottom: 5),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('· ', style: TextStyle(color: KwColors.faint)),
                        Expanded(
                          child: Text(
                            s.toString(),
                            style: TextStyle(
                              fontSize: 12,
                              color: KwColors.dim,
                              height: 1.5,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
            ],
          ),
        ),
        actions: [
          FilledButton(onPressed: () => Navigator.pop(ctx), child: Text('完成')),
        ],
      ),
    );
  }

  /* ------------------------------------------------------------------ */
  /* 备份 / sshd                                                         */
  /* ------------------------------------------------------------------ */

  Future<void> _openBackups() async {
    List<Map<String, dynamic>> list;
    try {
      list = await state.backups();
    } catch (e) {
      if (mounted) showError(context, e);
      return;
    }
    if (!mounted) return;
    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: KwColors.bgElev,
      builder: (ctx) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          padding: EdgeInsets.all(16),
          children: [
            Text(
              'authorized_keys 历史备份',
              style: TextStyle(
                fontSize: 15,
                fontWeight: FontWeight.w600,
                color: KwColors.text,
              ),
            ),
            SizedBox(height: 6),
            Text(
              '恢复前会自动再备份当前文件；空备份硬性拒绝。',
              style: TextStyle(fontSize: 12, color: KwColors.dim),
            ),
            Divider(height: 22, color: KwColors.border),
            if (list.isEmpty)
              Padding(
                padding: EdgeInsets.symmetric(vertical: 16),
                child: Text(
                  '还没有备份',
                  style: TextStyle(fontSize: 13, color: KwColors.dim),
                ),
              ),
            ...list.map(
              (b) => ListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(
                  b['displayTime']?.toString() ?? b['name'].toString(),
                  style: TextStyle(
                    fontSize: 13,
                    fontFamily: 'monospace',
                    color: KwColors.text,
                  ),
                ),
                subtitle: Text(
                  b['name']?.toString() ?? '',
                  style: TextStyle(
                    fontSize: 10.5,
                    fontFamily: 'monospace',
                    color: KwColors.faint,
                  ),
                ),
                trailing: Icon(
                  Icons.chevron_right_rounded,
                  size: 18,
                  color: KwColors.faint,
                ),
                onTap: () {
                  Navigator.pop(ctx);
                  _openDiff(b['name'].toString());
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _openDiff(String name) async {
    Map<String, dynamic> diff;
    try {
      diff = await state.backupDiff(name);
    } catch (e) {
      if (mounted) showError(context, e);
      return;
    }
    if (!mounted) return;
    final restore = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('备份差异'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                '备份 ${diff['backupKeyCount']} 把 · 当前 ${diff['currentKeyCount']} 把 · '
                '相同 ${diff['sameCount']} 把',
                style: TextStyle(fontSize: 12.5, color: KwColors.text),
              ),
              SizedBox(height: 8),
              _diffBlock('恢复后新增', diff['added'], KwColors.ok),
              _diffBlock('恢复后移除', diff['removed'], KwColors.danger),
              if (diff['emptyBackup'] == true)
                Text(
                  '空备份，服务端会拒绝恢复',
                  style: TextStyle(fontSize: 12, color: KwColors.danger),
                ),
              if (diff['usedKeyInBackup'] == false)
                Text(
                  '这份备份不含本次连接正在使用的钥匙，恢复后下次连接会失败。',
                  style: TextStyle(
                    fontSize: 12,
                    color: KwColors.warn,
                    height: 1.5,
                  ),
                ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text('取消'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: KwColors.warn),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text('恢复'),
          ),
        ],
      ),
    );
    if (restore != true || !mounted) return;

    try {
      var data = await state.restoreBackup(name);
      if (data['needsForce'] == true && mounted) {
        final force = await confirm(
          context,
          title: '需要强制确认',
          message: data['message']?.toString() ?? '备份不含当前登录钥匙。',
          confirmText: '强制恢复',
          danger: true,
        );
        if (!force) return;
        data = await state.restoreBackup(name, force: true);
      }
      if (mounted) {
        showSnack(context, '已恢复', ok: true);
      }
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }

  Widget _diffBlock(String title, dynamic raw, Color color) {
    final list = raw is List ? raw : [];
    if (list.isEmpty) return SizedBox.shrink();
    return Padding(
      padding: EdgeInsets.only(bottom: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            '$title（${list.length}）',
            style: TextStyle(fontSize: 12, color: color),
          ),
          SizedBox(height: 4),
          ...list.map((e) {
            final map = e is Map ? e : {};
            final label = (map['comment']?.toString().isNotEmpty ?? false)
                ? map['comment'].toString()
                : shortFp(map['fingerprint']?.toString() ?? '');
            return Text(
              '· $label',
              style: TextStyle(
                fontSize: 11,
                fontFamily: 'monospace',
                color: KwColors.dim,
              ),
            );
          }),
        ],
      ),
    );
  }

  Future<void> _openSshd() async {
    if (state.sshd == null) {
      try {
        await state.loadSshd();
      } catch (e) {
        if (mounted) showError(context, e);
        return;
      }
    }
    if (!mounted) return;
    final sshd = state.sshd;
    if (sshd == null) {
      showSnack(context, '无法读取 sshd 状态', danger: true);
      return;
    }
    final available = sshd['available'] == true;
    final keyOnly = sshd['keyOnly'] == true;

    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: KwColors.bgElev,
      builder: (ctx) => SafeArea(
        child: Padding(
          padding: EdgeInsets.all(16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                '服务器登录方式',
                style: TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                  color: KwColors.text,
                ),
              ),
              SizedBox(height: 8),
              if (!available)
                Text(
                  sshd['reason']?.toString() ?? '无法读取 sshd 配置',
                  style: TextStyle(
                    fontSize: 12.5,
                    color: KwColors.warn,
                    height: 1.5,
                  ),
                )
              else ...[
                Text(
                  keyOnly
                      ? '仅密钥登录已开启：password / kbd-interactive 都已关闭。'
                      : '当前仍允许密码登录（PasswordAuthentication 或 '
                            'KbdInteractiveAuthentication 至少一个为 yes）。',
                  style: TextStyle(
                    fontSize: 12.5,
                    color: KwColors.dim,
                    height: 1.6,
                  ),
                ),
                SizedBox(height: 10),
                Text(
                  '配置来源：${(sshd['files'] is List ? (sshd['files'] as List).join('、') : '/etc/ssh/sshd_config')}\n'
                  '权限：${sshd['isRoot'] == true ? 'root' : (sshd['sudo'] == true ? '免密 sudo' : '只读')}',
                  style: TextStyle(
                    fontSize: 11,
                    fontFamily: 'monospace',
                    color: KwColors.faint,
                    height: 1.5,
                  ),
                ),
                SizedBox(height: 14),
                SizedBox(
                  width: double.infinity,
                  child: FilledButton(
                    style: keyOnly
                        ? FilledButton.styleFrom(backgroundColor: KwColors.warn)
                        : null,
                    onPressed: sshd['canWrite'] == true
                        ? () {
                            Navigator.pop(ctx);
                            _toggleSshd(!keyOnly);
                          }
                        : null,
                    child: Text(
                      keyOnly ? '重新允许密码登录' : '开启仅密钥登录',
                      style: TextStyle(fontSize: 13),
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _toggleSshd(bool enable) async {
    final ok = await confirm(
      context,
      title: enable ? '开启仅密钥登录' : '允许密码登录',
      message: enable
          ? '会关闭 PasswordAuthentication 与 KbdInteractiveAuthentication'
                '（含 sshd_config.d 里的 drop-in），并确保 PubkeyAuthentication yes。\n\n'
                '开启前会确认：当前是密钥登录、这把钥匙确实在 authorized_keys 里。'
                '语法校验失败会自动回滚。'
          : '重新允许密码登录会降低服务器安全性，确定继续？',
      confirmText: enable ? '开启' : '允许',
      danger: !enable,
    );
    if (!ok || !mounted) return;
    try {
      final data = await state.setKeyOnly(enable);
      if (!mounted) return;
      final effective = data['effective'] == true;
      final warning = data['warning']?.toString() ?? '';
      showSnack(
        context,
        effective
            ? (enable ? '已开启仅密钥登录' : '已恢复密码登录')
            : (warning.isEmpty ? '配置已写入，但未生效' : warning),
        ok: effective,
        danger: !effective,
      );
    } catch (e) {
      if (mounted) showError(context, e);
    }
  }
}
