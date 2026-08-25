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
        builtIn: '内置账户', noData: '没有匹配的用户', myPassword: '我的密码', passwordNote: '更新后其他登录会话将失效',
        changePassword: '修改密码', retry: '重试', cancel: '取消', save: '保存', reset: '重置',
        createTitle: '新建用户', createCopy: '创建可登录网关的身份账户。', username: '用户名', initialPassword: '初始密码',
        roleHint: '从 admin、staff、user、viewer 中选择一个或多个角色', createAction: '创建用户', rolesTitle: '设置角色', rolesHint: '角色用于统一控制管理和应用访问权限',
        resetTitle: '重置密码', resetCopy: '设置新密码', newPassword: '新密码', myPasswordTitle: '修改我的密码',
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
        routesTitle: '域名与端口绑定', routesCopy: '固定域名映射到本机服务端口', routeCount: '条路由', domain: '域名前缀', port: '端口', status: '状态', note: '备注', menuName: '菜单名称', websocket: 'WebSocket', noBindings: '尚未创建固定绑定',
        policiesTitle: 'Casbin 策略', policiesCopy: '拒绝规则优先匹配；对象格式为 /<端口><路径>', search: '搜索主体或对象',
        type: '类型', subject: '主体', objectRole: '对象 / 角色', action: '动作', effect: '效果', retry: '重试', cancel: '取消', local: '本地', dingtalk: '钉钉', wechat: '微信',
        bindingTitle: '新增域名绑定', editBindingTitle: '编辑域名绑定', bindingCopy: '填写最后一级前缀，例如 name1；系统会拼接当前实例域名。', domainPlaceholder: 'name1', menuNameHint: '填写后直接作为左侧菜单名称', websocketEnabled: 'WebSocket 自动代理', websocketHint: '所有已解析的代理目标默认转发 WebSocket 升级请求', enabledNow: '立即启用', createBinding: '创建绑定', saveBinding: '保存绑定', editBinding: '编辑绑定',
        policyTitle: '新增访问策略', policyCopy: '创建授权规则或用户角色分配。', policyType: '策略类型', user: '用户', role: '角色', object: '对象', httpAction: 'HTTP 动作', createPolicy: '创建策略',
        subjectHint: '选择角色或具体用户', userHint: '选择需要分配角色的用户', roleHint: '策略主体支持 admin、staff、user、viewer 或 api', objectHint: '选择绑定地址，或输入 /<端口><路径>', httpActionHint: '可选择多个标准 HTTP 方法；* 表示全部方法', allObjects: '全部地址 · /*', allActions: '全部方法 · *', allow: '允许', deny: '拒绝', assigned: '已分配',
        policyRule: '授权规则', roleAssignment: '角色分配', deleteBinding: '删除绑定', deletePolicy: '删除策略',
        required: '此项不能为空', bindingCreated: '绑定已创建', bindingUpdated: '绑定已更新', bindingDisabled: '绑定已停用', bindingEnabled: '绑定已启用',
        deleteBindingTitle: '删除域名绑定', deleteBindingConfirm: '确认删除此域名绑定？', deleteAction: '删除', bindingDeleted: '绑定已删除',
        policyCreated: '策略已创建', deletePolicyTitle: '删除访问策略', deletePolicyConfirm: '权限结果可能立即改变。', policyDeleted: '策略已删除'
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
        builtIn: 'Built-in', noData: 'No matching users', myPassword: 'My password', passwordNote: 'Other sessions expire after an update',
        changePassword: 'Change password', retry: 'Retry', cancel: 'Cancel', save: 'Save', reset: 'Reset',
        createTitle: 'New user', createCopy: 'Create an identity that can sign in to the gateway.', username: 'Username', initialPassword: 'Initial password',
        roleHint: 'Select one or more roles from admin, staff, user, and viewer', createAction: 'Create user', rolesTitle: 'Set roles', rolesHint: 'Roles consistently control administrative and application access',
        resetTitle: 'Reset password', resetCopy: 'Set a new password', newPassword: 'New password', myPasswordTitle: 'Change my password',
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
        routesTitle: 'Domain and port bindings', routesCopy: 'Map fixed domains to local service ports', routeCount: 'routes', domain: 'Domain prefix', port: 'Port', status: 'Status', note: 'Note', menuName: 'Menu name', websocket: 'WebSocket', noBindings: 'No fixed bindings yet',
        policiesTitle: 'Casbin policies', policiesCopy: 'Deny rules match first; object format is /<port><path>', search: 'Search subjects or objects',
        type: 'Type', subject: 'Subject', objectRole: 'Object / Role', action: 'Action', effect: 'Effect', retry: 'Retry', cancel: 'Cancel', local: 'Local', dingtalk: 'DingTalk', wechat: 'WeChat',
        bindingTitle: 'Add domain binding', editBindingTitle: 'Edit domain binding', bindingCopy: 'Enter the last-level prefix, such as name1; the instance domain is appended automatically.', domainPlaceholder: 'name1', menuNameHint: 'When set, this is used in the left menu', websocketEnabled: 'WebSocket auto-proxy', websocketHint: 'All resolved proxy targets forward WebSocket upgrade requests by default', enabledNow: 'Enable now', createBinding: 'Create binding', saveBinding: 'Save binding', editBinding: 'Edit binding',
        policyTitle: 'Add access policy', policyCopy: 'Create an authorization rule or assign a user role.', policyType: 'Policy type', user: 'User', role: 'Role', object: 'Object', httpAction: 'HTTP action', createPolicy: 'Create policy',
        subjectHint: 'Select a role or a specific user', userHint: 'Select the user receiving the role', roleHint: 'Policy subjects support admin, staff, user, viewer, or api', objectHint: 'Select a binding or enter /<port><path>', httpActionHint: 'Select multiple standard HTTP methods; * matches every method', allObjects: 'All objects · /*', allActions: 'All methods · *', allow: 'Allow', deny: 'Deny', assigned: 'Assigned',
        policyRule: 'Access rule', roleAssignment: 'Role assignment', deleteBinding: 'Delete binding', deletePolicy: 'Delete policy',
        required: 'This field is required', bindingCreated: 'Binding created', bindingUpdated: 'Binding updated', bindingDisabled: 'Binding disabled', bindingEnabled: 'Binding enabled',
        deleteBindingTitle: 'Delete domain binding', deleteBindingConfirm: 'Delete this domain binding?', deleteAction: 'Delete', bindingDeleted: 'Binding deleted',
        policyCreated: 'Policy created', deletePolicyTitle: 'Delete access policy', deletePolicyConfirm: 'Authorization results may change immediately.', policyDeleted: 'Policy deleted'
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
