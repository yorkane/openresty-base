const { createApp, computed, onBeforeUnmount, onMounted, ref } = Vue

const allowedApps = new Set([
  'apps/users.html',
  'apps/authorization.html'
])

const app = createApp({
  setup () {
    const drawerVisible = ref(true)
    const drawerMini = ref(window.innerWidth < 760)
    const activeApp = ref('apps/users.html')
    const activeTitle = ref('用户 / 角色管理')
    const authenticated = ref(false)
    const isAdmin = ref(false)
    const username = ref('正在验证')
    const source = ref('')
    const csrf = ref('')
    const applications = ref([])
    const locale = ref(window.adminI18n.getLocale())
    const i18n = computed(() => window.adminI18n.messages[locale.value].menu)
    const displayName = computed(() => source.value && source.value !== 'local'
      ? `${username.value} · ${source.value}`
      : username.value)
    const toggleIcon = computed(() => drawerMini.value ? 'mdi-chevron-right' : 'mdi-chevron-left')
    const toggleLabel = computed(() => drawerMini.value ? i18n.value.expand : i18n.value.collapse)
    let unsubscribeLocale
    let applicationsTimer

    const menuItems = computed(() => {
      const items = [
        { app: 'apps/users.html', title: i18n.value.usersTitle, label: i18n.value.users, icon: 'mdi-account-group-outline' }
      ]
      if (isAdmin.value) {
        items.push({ app: 'apps/authorization.html', title: i18n.value.authorizationTitle, label: i18n.value.authorization, icon: 'mdi-shield-key-outline' })
      }
      applications.value.forEach(application => {
        const appUrl = applicationUrl(application.port)
        items.push({
          app: appUrl,
          title: application.note || application.domain,
          label: application.note || application.domain,
          icon: 'mdi-application-outline'
        })
      })
      return items
    })

    function applicationUrl (port) {
      const hostname = window.location.hostname
      const gatewayPort = window.location.port ? `:${window.location.port}` : ''
      return `${window.location.protocol}//${port}-${hostname}${gatewayPort}/`
    }

    function navigate (item) {
      if (!allowedApps.has(item.app) && !item.app.startsWith(`${window.location.protocol}//`)) return
      activeApp.value = item.app
      activeTitle.value = item.title
    }

    function toggleDrawer () {
      drawerMini.value = !drawerMini.value
    }

    function syncDrawerState () {
      drawerMini.value = window.innerWidth < 760
    }

    function toggleLocale () {
      window.adminI18n.setLocale(locale.value === 'zh-CN' ? 'en-US' : 'zh-CN')
    }

    async function loadApplications () {
      try {
        applications.value = await window.adminApi.applications()
      } catch (error) {
        if (error?.status === 401) return window.location.replace('/_authz/login?next=%2F_radmin_%2F')
        console.error('Unable to load local applications:', error)
      }
    }

    async function loadSession () {
      try {
        const session = await window.adminApi.session()
        authenticated.value = true
        isAdmin.value = Boolean(session.admin)
        username.value = session.username || 'Signed in'
        source.value = session.source || 'local'
        csrf.value = session.csrf || ''
        await loadApplications()
      } catch (error) {
        if (error?.status === 401) {
          window.location.replace('/_authz/login?next=%2F_radmin_%2F')
          return
        }
        username.value = '服务不可用'
        console.error('Unable to load admin session:', error)
      }
    }

    async function logout () {
      try {
        await window.adminApi.logout({ _csrf: csrf.value })
      } finally {
        window.location.href = '/_authz/login'
      }
    }

    onMounted(() => {
      window.addEventListener('resize', syncDrawerState)
      unsubscribeLocale = window.adminI18n.subscribe(nextLocale => {
        locale.value = nextLocale
        Quasar.Lang.set(nextLocale === 'zh-CN' ? Quasar.Lang.zhCN : Quasar.Lang.enUS)
      })
      loadSession().then(() => {
        applicationsTimer = window.setInterval(loadApplications, 30000)
      })
    })

    onBeforeUnmount(() => {
      window.removeEventListener('resize', syncDrawerState)
      window.clearInterval(applicationsTimer)
      unsubscribeLocale?.()
    })

    return {
      activeApp,
      activeTitle,
      authenticated,
      displayName,
      drawerMini,
      drawerVisible,
      i18n,
      isAdmin,
      locale,
      logout,
      applications,
      menuItems,
      navigate,
      toggleDrawer,
      toggleIcon,
      toggleLabel,
      toggleLocale
    }
  }
})

app.use(Quasar)
Quasar.Lang.set(window.adminI18n.getLocale() === 'en-US' ? Quasar.Lang.enUS : Quasar.Lang.zhCN)
Quasar.IconSet.set(Quasar.IconSet.mdiV7)
app.mount('#q-app')
