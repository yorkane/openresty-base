(function () {
  const messages = {
    'zh-CN': {
      menu: {
        workspace: '工作区', users: '用户与角色', usersTitle: '用户 / 角色管理',
        authorization: '授权策略', authorizationTitle: '授权管理', logout: '注销', language: 'English',
        collapse: '收起菜单', expand: '展开菜单'
      },
      users: {
        title: '用户与角色', description: '集中管理登录账户、角色和凭据安全。', create: '新建用户',
        accounts: '账户总数', accountsNote: '网关身份', enabled: '启用', disabled: '未启用', enabledNote: '允许登录',
        roles: '角色数量', rolesNote: '不同访问角色', allUsers: '全部用户', protectedAdmin: '管理员账户受到额外保护', myProfile: '我的信息', myProfileNote: '仅显示当前登录身份与角色',
        search: '搜索用户、来源或角色', user: '用户', source: '来源', local: '本地', dingtalk: '钉钉', wechat: '微信', role: '角色', status: '状态', createdAt: '创建日期', lastLoginAt: '用户登录日期', updatedAt: '修改日期',
        builtIn: '内置账户', noData: '没有匹配的用户', myPassword: '我的密码', passwordNote: '更新后所有登录会话将失效，请重新登录',
        changePassword: '修改密码', retry: '重试', cancel: '取消', save: '保存', reset: '重置',
        createTitle: '新建用户', createCopy: '创建可登录网关的身份账户。', username: '用户名', initialPassword: '初始密码',
        roleHint: '从 admin、staff、user、viewer 中选择一个或多个角色', createAction: '创建用户', rolesTitle: '设置角色', rolesHint: '角色用于统一控制管理和应用访问权限',
        resetTitle: '重置密码', resetCopy: '设置新密码', newPassword: '新密码', confirmNewPassword: '确认新密码', passwordMismatch: '两次输入的新密码不一致', myPasswordTitle: '修改我的密码',
        myPasswordCopy: '请先验证当前密码。', currentPassword: '当前密码', updatePassword: '更新密码',
        required: '此项不能为空', usernameRule: '使用 2-32 位小写字母、数字、_ 或 -', passwordRule: '密码至少 6 位', roleRule: '请从 admin、staff、user、viewer 中至少选择一个角色',
        created: '用户已创建', rolesUpdated: '角色已更新', passwordReset: '密码已重置', enabledDone: '用户已设为启用',
        disabledDone: '用户已设为未启用', disableTitle: '设为未启用', disableConfirm: '该用户的现有会话将失效，并且无法继续登录。',
        deleteTitle: '删除用户', deleteConfirm: '此操作无法撤销。', deleteRemoteConfirm: '将删除本机身份记录、会话和直接授权；下次认证时会重新记录。', deleteAction: '删除', deleted: '用户已删除', passwordUpdated: '密码已更新',
        remoteRoles: '远端角色记录', remoteRolesHint: '保存只覆盖本机有效角色，不会回写身份源；下次登录仅刷新远端记录', remoteRolesUpdated: '本机角色覆盖已保存', restoreRemote: '恢复记录角色', restoreRemoteConfirm: '将清除本机角色覆盖并恢复最近记录的远端角色。', remoteRolesRestored: '已恢复记录角色'
      },
      authorization: {
        title: '授权管理', description: '管理入口映射与 Casbin 访问决策。', addBinding: '新增绑定', addPolicy: '新增策略',
        bindings: '域名绑定', bindingsNote: '固定路由', allowPolicies: '允许策略', allowNote: '允许访问', denyPolicies: '拒绝策略', denyNote: '拒绝优先',
        routesTitle: '域名与端口绑定', routesCopy: '固定域名映射到本机或其他 IP 的 HTTP 服务', routeCount: '条路由', domain: '域名前缀', targetIp: '目标 IP', port: '端口', status: '状态', note: '备注', menuName: '菜单名称', websocket: 'WebSocket', proxyMode: '代理方式', noBindings: '尚未创建固定绑定',
        policiesTitle: 'Casbin 策略', policiesCopy: '拒绝规则优先匹配；对象格式为 /<端口><路径>', search: '搜索主体或对象',
        type: '类型', subject: '主体', objectRole: '对象 / 角色', action: '动作', effect: '效果', retry: '重试', cancel: '取消', local: '本地', dingtalk: '钉钉', wechat: '微信',
        bindingTitle: '新增域名绑定', editBindingTitle: '编辑域名绑定', bindingCopy: '填写最后一级前缀与目标地址；代理细节按需展开。', domainPlaceholder: 'name1', targetIpPlaceholder: '127.0.0.1', targetIpHint: '默认代理本机；也可填写其他机器的 IPv4 或 IPv6 地址', menuNameHint: '填写后直接作为左侧菜单名称', websocketEnabled: 'WebSocket 自动代理', websocketHint: '所有目标默认支持升级请求', enabledNow: '立即启用', createBinding: '创建绑定', saveBinding: '保存绑定', editBinding: '编辑绑定',
        advancedProxy: '高级代理配置', advancedProxyHint: 'Host、Forwarded 与 Origin', upstreamHost: '上游 Host', upstreamHostPlaceholder: '留空：使用访问域名', upstreamHostHint: '发送给后端的 Host 请求头', forwardedHost: 'X-Forwarded-Host', forwardedHostPlaceholder: '留空：跟随上游 Host', forwardedHostHint: '发送给后端的原始主机名', forwardedProto: 'X-Forwarded-Proto', forwardedPort: 'X-Forwarded-Port', autoValue: '自动', originMode: 'Origin 处理', originAuto: '自动（默认保持）', originPreserve: '保持请求值', originRewrite: '按代理地址重写', originRemove: '移除 Origin', originCustom: '使用自定义值', customOrigin: '自定义 Origin', simulateLocal: '模拟本机访问', simulateLocalHint: '使用目标地址作为默认 Host，并把来源请求头改为指定的本机或局域网 IP', localIp: '模拟来源 IP', localIpHint: '默认 127.0.0.1；也可填写网关局域网 IP', proxyDefault: '默认', proxyCustom: '自定义', proxyLocal: '模拟本机',
        policyTitle: '新增访问策略', editPolicyTitle: '编辑访问策略', policyCopy: '创建 P 类型访问授权规则。', user: '用户', role: '角色', object: '对象', objectAddress: '绑定对象', objectPath: '访问路径', objectPreview: '授权对象', httpAction: 'HTTP 动作', createPolicy: '创建策略', savePolicy: '保存策略', editPolicy: '编辑策略',
        subjectHint: '选择角色或具体用户', userHint: '选择需要分配角色的用户', roleHint: '策略主体支持 admin、staff、user、viewer 或 api', objectHint: '按菜单名、域名和目标地址选择；也可输入 /<端口><路径>', objectAddressRule: '请选择绑定对象或输入 /<端口><路径>', objectPathRule: '路径必须以 / 开头，且不能包含空格或逗号', httpActionHint: '可选择多个标准 HTTP 方法；* 表示全部方法', allObjects: '全部地址 · /*', allObjectsHint: '匹配所有绑定、端口和路径', directPort: '直接端口', sharedBindings: '个绑定共享', unboundObject: '未找到对应绑定', invalidObject: '无效对象', allActions: '全部方法 · *', allow: '允许', deny: '拒绝', assigned: '已分配',
        deleteBinding: '删除绑定', deletePolicy: '删除策略',
        required: '此项不能为空', bindingCreated: '绑定已创建', bindingUpdated: '绑定已更新', bindingDisabled: '绑定已停用', bindingEnabled: '绑定已启用',
        deleteBindingTitle: '删除域名绑定', deleteBindingConfirm: '确认删除此域名绑定？', deleteAction: '删除', bindingDeleted: '绑定已删除',
        policyCreated: '策略已创建', policyUpdated: '策略已更新', deletePolicyTitle: '删除访问策略', deletePolicyConfirm: '权限结果可能立即改变。', policyDeleted: '策略已删除'
      }
    },
    'en-US': {
      menu: {
        workspace: 'Workspace', users: 'Users & Roles', usersTitle: 'Users & Roles',
        authorization: 'Authorization', authorizationTitle: 'Authorization', logout: 'Logout', language: '中文',
        collapse: 'Collapse menu', expand: 'Expand menu'
      },
      users: {
        title: 'Users & Roles', description: 'Manage sign-in accounts, roles, and credential security.', create: 'New user',
        accounts: 'Total accounts', accountsNote: 'Gateway identities', enabled: 'Enabled', disabled: 'Disabled', enabledNote: 'Allowed to sign in',
        roles: 'Roles', rolesNote: 'Distinct access roles', allUsers: 'All users', protectedAdmin: 'The administrator account has additional protection', myProfile: 'My profile', myProfileNote: 'Only the current identity and roles are shown',
        search: 'Search users, sources, or roles', user: 'User', source: 'Source', local: 'Local', dingtalk: 'DingTalk', wechat: 'WeChat', role: 'Role', status: 'Status', createdAt: 'Created at', lastLoginAt: 'Last login at', updatedAt: 'Updated at',
        builtIn: 'Built-in', noData: 'No matching users', myPassword: 'My password', passwordNote: 'All sessions expire after an update; sign in again',
        changePassword: 'Change password', retry: 'Retry', cancel: 'Cancel', save: 'Save', reset: 'Reset',
        createTitle: 'New user', createCopy: 'Create an identity that can sign in to the gateway.', username: 'Username', initialPassword: 'Initial password',
        roleHint: 'Select one or more roles from admin, staff, user, and viewer', createAction: 'Create user', rolesTitle: 'Set roles', rolesHint: 'Roles consistently control administrative and application access',
        resetTitle: 'Reset password', resetCopy: 'Set a new password', newPassword: 'New password', confirmNewPassword: 'Confirm new password', passwordMismatch: 'The new passwords do not match', myPasswordTitle: 'Change my password',
        myPasswordCopy: 'Verify the current password first.', currentPassword: 'Current password', updatePassword: 'Update password',
        required: 'This field is required', usernameRule: 'Use 2-32 lowercase letters, numbers, _ or -', passwordRule: 'Password must be at least 6 characters', roleRule: 'Select at least one of admin, staff, user, or viewer',
        created: 'User created', rolesUpdated: 'Roles updated', passwordReset: 'Password reset', enabledDone: 'User enabled',
        disabledDone: 'User disabled', disableTitle: 'Disable user', disableConfirm: 'Existing sessions expire and this user can no longer sign in.',
        deleteTitle: 'Delete user', deleteConfirm: 'This action cannot be undone.', deleteRemoteConfirm: 'The local identity record, sessions, and direct grants are removed. The identity is recorded again on its next authentication.', deleteAction: 'Delete', deleted: 'User deleted', passwordUpdated: 'Password updated',
        remoteRoles: 'Recorded remote roles', remoteRolesHint: 'Saving only overrides effective local roles and never writes back to the identity provider; the next login only refreshes the record', remoteRolesUpdated: 'Local role override saved', restoreRemote: 'Restore recorded roles', restoreRemoteConfirm: 'Clear the local override and restore the most recently recorded remote roles.', remoteRolesRestored: 'Recorded roles restored'
      },
      authorization: {
        title: 'Authorization', description: 'Manage gateway mappings and Casbin access decisions.', addBinding: 'Add binding', addPolicy: 'Add policy',
        bindings: 'Domain bindings', bindingsNote: 'Explicit routes', allowPolicies: 'Allow policies', allowNote: 'Allow decisions', denyPolicies: 'Deny policies', denyNote: 'Deny takes priority',
        routesTitle: 'Domain and port bindings', routesCopy: 'Map fixed domains to HTTP services on this or another IP', routeCount: 'routes', domain: 'Domain prefix', targetIp: 'Target IP', port: 'Port', status: 'Status', note: 'Note', menuName: 'Menu name', websocket: 'WebSocket', proxyMode: 'Proxy mode', noBindings: 'No fixed bindings yet',
        policiesTitle: 'Casbin policies', policiesCopy: 'Deny rules match first; object format is /<port><path>', search: 'Search subjects or objects',
        type: 'Type', subject: 'Subject', objectRole: 'Object / Role', action: 'Action', effect: 'Effect', retry: 'Retry', cancel: 'Cancel', local: 'Local', dingtalk: 'DingTalk', wechat: 'WeChat',
        bindingTitle: 'Add domain binding', editBindingTitle: 'Edit domain binding', bindingCopy: 'Enter the last-level prefix and target; expand proxy details only when needed.', domainPlaceholder: 'name1', targetIpPlaceholder: '127.0.0.1', targetIpHint: 'Defaults to this host; another IPv4 or IPv6 address is also accepted', menuNameHint: 'When set, this is used in the left menu', websocketEnabled: 'WebSocket auto-proxy', websocketHint: 'Upgrade requests are supported for every target', enabledNow: 'Enable now', createBinding: 'Create binding', saveBinding: 'Save binding', editBinding: 'Edit binding',
        advancedProxy: 'Advanced proxy settings', advancedProxyHint: 'Host, Forwarded, and Origin', upstreamHost: 'Upstream Host', upstreamHostPlaceholder: 'Blank: use request domain', upstreamHostHint: 'Host header sent to the upstream', forwardedHost: 'X-Forwarded-Host', forwardedHostPlaceholder: 'Blank: follow upstream Host', forwardedHostHint: 'Original host reported to the upstream', forwardedProto: 'X-Forwarded-Proto', forwardedPort: 'X-Forwarded-Port', autoValue: 'Auto', originMode: 'Origin handling', originAuto: 'Auto (preserve by default)', originPreserve: 'Preserve request value', originRewrite: 'Rewrite to proxy address', originRemove: 'Remove Origin', originCustom: 'Use custom value', customOrigin: 'Custom Origin', simulateLocal: 'Simulate local access', simulateLocalHint: 'Use the target as the default Host and replace source headers with a local or LAN address', localIp: 'Simulated source IP', localIpHint: 'Defaults to 127.0.0.1; the gateway LAN IP is also accepted', proxyDefault: 'Default', proxyCustom: 'Custom', proxyLocal: 'Local simulation',
        policyTitle: 'Add access policy', editPolicyTitle: 'Edit access policy', policyCopy: 'Create a P-type access authorization rule.', user: 'User', role: 'Role', object: 'Object', objectAddress: 'Binding target', objectPath: 'Access path', objectPreview: 'Policy object', httpAction: 'HTTP action', createPolicy: 'Create policy', savePolicy: 'Save policy', editPolicy: 'Edit policy',
        subjectHint: 'Select a role or a specific user', userHint: 'Select the user receiving the role', roleHint: 'Policy subjects support admin, staff, user, viewer, or api', objectHint: 'Select by menu, domain, and target; or enter /<port><path>', objectAddressRule: 'Select a binding or enter /<port><path>', objectPathRule: 'Path must start with / and contain no spaces or commas', httpActionHint: 'Select multiple standard HTTP methods; * matches every method', allObjects: 'All objects · /*', allObjectsHint: 'Matches every binding, port, and path', directPort: 'Direct port', sharedBindings: 'shared bindings', unboundObject: 'No matching binding', invalidObject: 'Invalid object', allActions: 'All methods · *', allow: 'Allow', deny: 'Deny', assigned: 'Assigned',
        deleteBinding: 'Delete binding', deletePolicy: 'Delete policy',
        required: 'This field is required', bindingCreated: 'Binding created', bindingUpdated: 'Binding updated', bindingDisabled: 'Binding disabled', bindingEnabled: 'Binding enabled',
        deleteBindingTitle: 'Delete domain binding', deleteBindingConfirm: 'Delete this domain binding?', deleteAction: 'Delete', bindingDeleted: 'Binding deleted',
        policyCreated: 'Policy created', policyUpdated: 'Policy updated', deletePolicyTitle: 'Delete access policy', deletePolicyConfirm: 'Authorization results may change immediately.', policyDeleted: 'Policy deleted'
      }
    }
  }

  function normalize (locale) {
    return locale === 'en-US' ? 'en-US' : 'zh-CN'
  }

  function getLocale () {
    return normalize(window.localStorage.getItem('admin_locale'))
  }

  function setLocale (locale) {
    const nextLocale = normalize(locale)
    window.localStorage.setItem('admin_locale', nextLocale)
    window.top.postMessage({ type: 'admin-locale-change', locale: nextLocale }, window.location.origin)
    return nextLocale
  }

  function subscribe (callback) {
    const handleStorage = event => {
      if (event.key === 'admin_locale') callback(normalize(event.newValue))
    }
    const handleMessage = event => {
      if (event.origin === window.location.origin && event.data?.type === 'admin-locale-change') {
        callback(normalize(event.data.locale))
      }
    }
    window.addEventListener('storage', handleStorage)
    window.addEventListener('message', handleMessage)
    return () => {
      window.removeEventListener('storage', handleStorage)
      window.removeEventListener('message', handleMessage)
    }
  }

  window.adminI18n = { getLocale, messages, setLocale, subscribe }
})()
