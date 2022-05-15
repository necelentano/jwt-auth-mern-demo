# JWT Authentication and Authorization Flow

## Теория и заметки по реализации

**Аутентификация** - в нашем случае, это процедура проверки подлинности пользователя при помощи логина и пароля.

**Авторизация** - предоставление пользователю прав на выполнение определённых действий (доступ к защищенным маршрутам). У пользователя могут быть специфичные роли с разными уровнями доступа.

### Сервер

Нам нужно создать маршруты для регистрации пользователя и для аутентификации пользователя (логин, логаут).

В контроллере обробатывающий регистрацию используем bcrypt (или аналоги) для хэширования пароля (нельзя хранить пароли в БД в чистом виде). В этот обработчик, как минимум должны передать уникальный идентификатор пользователя (имя, никнейм или email) и пароль. Если имя(email) уже существует в БД отвечаем со статусом 409 (Conflict).

Для логина, в теле запроса, также передадим имя (email) пользователя и пароль (если какое либо поле не предано отдаем статус 400). Если в БД не находим пользователя с указаным именем, возвращаем ответ со статусом 401 (Unauthorized). Если пользователь существует сравниваем пароли `bcrypt.compare()`. Если пароль совпадает то генерируем два JWT токена (accessToken и refreshToken) и отправляем их на клиент. Если нет, то отдаем статус 401.

#### Access-токен

Живет примерно 15-30 минут. Чем это время меньше тем безопаснее. Создается во время авторизации (логин). Клиент использует его для доступа к API пока не истечет срок жизни токена. Верифицируем при помощи middleware при каждом запросе (в этом примере это `middleware/verifyJWT.js`). Выпускаем новый Access токен при запросе к API refresh (в этом примере это `controllers/refreshTokenController.js`). Храним в памяти приложения. Хранить в localStorage и cookies без httpOnly (устанавливает только сервер) не безопасно.

В verifyJWT мы проверяем есть ли в запросе заголовок Authorization с Access токеном. Если есть то сверяем его `jwt.verify()` и добавляем нужные данные в запрос (в нашем примере в поля req.user и req.roles).

#### Refresh-токен

Живет уже дольше - 15-60 дней. Создается во время авторизации (логин). Клиент использует refreshToken для получения нового accessToken'а. Верифицируем при помощи запроса к endpointэ'у и БД. У него должно быть укзанное время жизни (не бесконечное), либо возможность его удалить при logout'е. Если в течении времени жизни refreshToken'а пользователь не посещал сервис, то ему придется заново авторизоваться при помощи логина (email) и пароля. Храним в httpOnly cookies, чтобы при помощи JS нельзя было получить к нему доступ. То есть куки устанваливает непосредственно сервер. Refresh-токен записывается в базу данных на сервере и получается своего рода сессия. Туда же можно записывать, например, IP адресс из которого произошло подключение (или браузер) и если при заходе будет новый адрес, то можно отправить письмо пользователю, что в его учетку зашли с нового устройства.

В качестве payload для JWT можем сипользовать **имя(никнейм, email)** и **роли** (права доступа), если нужно, но не пароль. Хорошей практикой будет использовать цифровой индикатор для описания роли, а не названия роли (user, editor, moderator, admin). Роли есть смысл передавать только для accessToken'а, но не для refreshToken'а (он нужен только для выпуска нового accessToken).

Вредоносные атаки, которые нужно учитывать: [XSS](https://ru.wikipedia.org/wiki/%D0%9C%D0%B5%D0%B6%D1%81%D0%B0%D0%B9%D1%82%D0%BE%D0%B2%D1%8B%D0%B9_%D1%81%D0%BA%D1%80%D0%B8%D0%BF%D1%82%D0%B8%D0%BD%D0%B3) и [CSRF](https://ru.wikipedia.org/wiki/%D0%9C%D0%B5%D0%B6%D1%81%D0%B0%D0%B9%D1%82%D0%BE%D0%B2%D0%B0%D1%8F_%D0%BF%D0%BE%D0%B4%D0%B4%D0%B5%D0%BB%D0%BA%D0%B0_%D0%B7%D0%B0%D0%BF%D1%80%D0%BE%D1%81%D0%B0)

#### Заметки по реализации

При авторизации (login) `controllers/authController.js` устанваливаем cookies с опциями httpOnly, sameSite, secure, maxAge.

Логика для logout'а пользователя описана в `controllers/logoutController.js` где мы удаляем refreshToken пользователя из БД и делаем `res.clearCookie()` (с опцией httpOnly и secure для https).

Также не стоит забывать про CORS ошибки. В этой реализации используем кастом credentials middleware (в ответе мы устанавливаем заголовок 'Access-Control-Allow-Credentials') и cors middleware (из npm) с опциями. Применяем в указаном порядке - сначала credentials, потом cors.

Роли для авторизации описываем в `config/roles_list.js`. Также модель User должна содержать поле, где указываем роли пользователя по умолчанию при создании пользователя.

Проверяем роли при помощи verifyRoles middleware куда предаем массив с ролями. В этой функции мы смотрим есть ли совпадения значений у переданного как аргумент массива и массива req.roles. Если совпадений нет то отдаем ответ со статусом 401, иначе next(). Пример использования verifyRoles middleware смотрим в `routes/api/employees.js`.

---

### Клиент

Используем HTTP-клиент Axios. В этой реализации создадим экземпляр axios и сразу укажем baseURL `client/src/api/axios.js`.

Регистрация нового пользователя происходит посредством обработчика handleSubmit в `components/Register.js`. В POST запросе также указываем опции - устанавливаем заголовок для Content-Type и указываем флаг `withCredentials: true`.

[withCredentials](https://developer.mozilla.org/ru/docs/Web/API/XMLHttpRequest/withCredentials): true - значит что кросс-доменные запросы Access-Control должны использовать какие-то реквизиты credentials - cookie или authorization headers. В нашем примере это нужно чтобы сервер (который размещен на другом домене) мог устанавливать cookie на домене клиента. Детали реализации смотрим в credentials middleware и cors middleware на сервере. Домен на котором развернут наш клиент должен быть в списке `server/config/allowedOrigins.js` иначе CORS будет блокировать запрос и мы никогда не получим ответ для аутетификации.

[Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/ru/docs/Web/HTTP/CORS).

Логика Login (вход в систему) пользователя описана в обработчике handleSubmit в `components/Login.js`. От сервера мы получаем роли и accessToken. Их мы храним в глобальном state.

#### Защищенные маршруты (Private routes)

В этом примере используется React Router 6. Структуру приложения с публичными и защищенными маршрутами смотрим в App.js.

Для создания защищенных маршрутов создадим компонент RequireAuth, где на основе состояния auth (есть ли пользователь и роли) мы рендерим дочерний компонент (Outlet) - сам защищенный маршрут. Роли (права доступа) для защищенного маршрута указываем как пропсы для RequireAuth.

В хуке `hooks/useRefreshToken` создаем функцию refresh, которая делает запрос на обновление нашего access токена. Повторимся, опция withCredentials позволяет отправлять куки с запросом к нашему API `/refresh` (но на клиенте мы никак не можем получить к ним доступ при помощи js). Функцию refresh мы будем вызывать когда наш первоначальный запрос будет неудачным (срок жизни accessToken истечет). После refresh'а мы получим новый токен и повторим запрос с уже с обновленным accessToken'ом.

Для запросов к защищенным маршрутам создадим новый, защищенный экземпляр объекта axios - смотрим в `client/src/api/axios.js`. Будем использовать его вместе с Access токеном. К этому axiosPrivate мы будем применять перехватчики interceptors - именно при помощи них мы будем прикреплять JWT accessToken и делать повторный запрос (retry), если запрос вначале пройдет неудачно.

Логика перехватчиков описана в хуке useAxiosPrivate. Он возвращает экземпляр axiosPrivate, к которому применили перехватчики interceptors. О самих перехватчиках можно думать примерно как о ванилных слушателях событий в JS. Мы можем их применить, но также нам нужна возможность их удаления. Иначе они будут применятся, и применятся и создадут кашу в наших запросах и ответах. Удаляем их в cleanup функции в useEffect.

В responseIntercept при ошибке 403 (когда accessToken просрочен) и когда у нас нет кастомного свойства sent мы делаем refresh токена и добавляем обновленный токена в заголовок Authorization. В конце условия опять вызываем axiosPrivate с новым accessToken. Если кастом свойство sent === true, значит мы уже обновляли accessToken и запрос вернет ошибку 403 (в консоли будет уже две ошибки 403).

В requestIntercept перед тем как сделать запрос мы проверям есть ли заголовок Authorization. Если его нет мы добавляем этот заголовок и берем accessToken из состояния приложения.

В дальнейшем используем экземпляр axiosPrivate для всех запросов к защищенным маршрутам в нашем API.

Пользователь этого не замечает, но каждый раз когда срок жизни AccessToken истекает, refreshToken, который хранится в защищеннух cookies (httpOnly) при помощи axios отправляется вместе с запросом к endpoint'у `/refresh`. После этого получаем новый accessToken и мы используем его для запросов к нашим защищенным маршрутам.

#### "Хранение данных" (Persist data)

Так как мы хотим хранить accessToken только в памяти приложения (Context, Redux ...), но не в localStorage или cookies, у нас возникает проблема - если мы перезагрузим страницу или уйдем, а потом вернемся на страницу - мы потерям accessToken. Решение - при загрузке/монтировании страницы делать запрос к серверу (refresh endpoint) для получения нового accessToken и сохранения его в памяти приложения. Мы можем делать этот запрос для каждого маршрута, но для оптимизации лучше делать этот запрос только для тех маршрутов, которые требуют аутентификации и авторизации.

**Особенности реализации.** Создадим компонент PersistLogin, в который будем обворачивать маршруты требующие аутентификации и авторизации. В этом компоненте мы при монтировании смотрим в состояние приложения, есть ли accessToken, если его нет, то делаем запрос на получение нового accessToken.

**Проблема безопасности 1.** Что если пользователь не вышел из своего аккаунта? Любой, кто получит доступ к устройству пользователя будет авторизован, пока не истечет срок жизни refreshToken'а. Нам нужно дать возможность самостоятельно "выйти" из своего аккаунта. Логика описана в хуке useLogout. Мы "очищаем" память (состояние) приложения и делаем запрос к API `/logout`, который удаляет refreshToken из httpOnly куки.

**Проблема безопасности 2.** Что если пользователь забыл выйти из своего аккаунта? Например, он вошел в свой аккаунт на устройстве с общим (публичным) доступом и, после взаимодействия с нашим сайтом, забыл из него выйти. В этом случае каждый другой пользователь устройства получит доступ к нашему сайту под учетными данными этого пользователя. **Решение.** Дать возможность пользователю указать доверяет ли он этому стройству или нет - добавить простой checkbox "Доверяете этому устройству?" (Trust this device). Добавим в наше состояние (хранилице) булевый флаг persist и синхронизируем его с localStorage (это не accessToken - не нарушает подход). В PersistLogin в условный рендер добавим проверку для persist. Если его значение false то react router будет рендерить Outlet (то есть защищенные маршруты, которые будут вести себя согласно их логике если в памяти нет accessToken). Хотя сам запрос на обновление accessToken в этой реализации мы делаем в любом случае и он даже будет храниться в памяти (состоянии) приложения. Если значение persist === true, показываем Loading и после рендерим Outlet (защищенные маршруты с accessToken). В компоненте Login добавим checkbox, который будет менять значение persist в глобальном состоянии и localStorage.

#### Лучшие практики по безопасности

1. Для production версии приложения отключить React Dev Tools и Redux Dev Tolls, чтобы недобросовестный пользователь не смог получить доступ к состоянию приложения и данным, которые там хранятся. Вероятные реализации: использовать пакеты из npm ([например](https://www.npmjs.com/package/@fvilers/disable-react-devtools)) или подобный [подход](https://remarkablemark.org/blog/2017/01/25/disable-react-devtools/). Для Redux (RTK) есть встроенные иснтрументы.
2. Всегда спрашивать себя должны ли мы хранить в памяти (состоянии) проложения те или иные данные? Конечно без хранения определенных данных нам не обойтись. Например, данные о пользователе, которые отображаются на странице или accessToken нам нужны. Но опредленно не стоит хранить какие то чувствительные данные - пароли или роли пользователя (хотя в первоначальной реализации мы хранили роли в памяти). Также хорошей практикой будет храние в памяти только тех данных, которые нам действиетльно нужны - когда мы получаем массив с пользователями в виде объектов с множеством полей, из которых нам нужно только одно поле или несколько. Если мы не используем данные из всех полей объекта, зачем их все хранить в состоянии? Идеальное решение это когда сервер отдает только нужные данные. Если у нас нет доступа к серверной части, то можно модифицировать код на клиенте чтобы хранить в состоянии только то, что нам действительно нужно.
3. Больше относится к серверу, но, при необходимости, актуально и для клиента. Если нам нужно хранить пароли (а нам нужно их хранить в БД), то **ВСЕГДА** храним их в зашифрованом виде. Для этого можно использовать пакеты `bcrypt` (для node.js) или bcryptjs (для использования на клиенте).
4. Если есть возможность держим данные в JWT и декодируем их из токена для использования. В этом репоизитории сервер отдает данные о пользователе (user), его роли (roles) и accessToken (JWT). Но, в качестве payload для нашего JWT, мы также храним его роли (смотрим в `server/controllers/authController.js` и `server/controllers/refreshTokenController.js` ). Поэтому в ответе сервера можно убрать массив с ролями пользователя. Вместо этого, на клиенте декодировать полученный JWT accessToken и взять данные о ролях пользователя из него. npm пакет для декодирования `jwt-decode`. Использование смотрим в `client/src/components/requireAuth.js`.

---

Ссылки:

- [Node.js Full Course for Beginners | Complete All-in-One Tutorial | 7 Hours](https://www.youtube.com/watch?v=f2EqECiTBL8)
- [React Login, Registration, and Authentication Playlist](https://www.youtube.com/playlist?list=PL0Zuz27SZ-6PRCpm9clX0WiBEMB70FWwd)
- [Axios Interceptors](https://axios-http.com/docs/interceptors)
- [Best Practices for React Data Security, Logins, Passwords, JWTs](https://www.youtube.com/watch?v=3QaFEu-KkR8)