import { axiosPrivate } from "../api/axios";
import { useEffect } from "react";
import useRefreshToken from "./useRefreshToken";
import useAuth from "./useAuth";

const useAxiosPrivate = () => {
    const refresh = useRefreshToken();
    const { auth } = useAuth();

    useEffect(() => {

        const requestIntercept = axiosPrivate.interceptors.request.use(
            config => {
                if (!config.headers['Authorization']) {
                    // если это первоначальный запрос, а не повторный, и заголовок с accessToken отсутствует (первоначальный после авторизации или после refresh'а)
                    config.headers['Authorization'] = `Bearer ${auth?.accessToken}`;
                }
                return config;
                // если заголовок Authorization уже установлен значит это повторная попытка после ошибки 403 - этот момент обрабатывается в responseIntercept при ошибке
            }, (error) => Promise.reject(error)
        );

        const responseIntercept = axiosPrivate.interceptors.response.use(
            response => response,
            async (error) => {
                // при ошибке сохраняем предыдущий запрос
                const prevRequest = error?.config;
                // если ответ сервера 403 и это первый запрос с ошибкой
                if (error?.response?.status === 403 && !prevRequest?.sent) {
                    prevRequest.sent = true;
                    const newAccessToken = await refresh();
                    prevRequest.headers['Authorization'] = `Bearer ${newAccessToken}`;
                    return axiosPrivate(prevRequest);
                }
                return Promise.reject(error);
            }
        );
        // удаляем interceptors иначе у нас может быть множество таких перехватчиков запроса и ответа
        return () => {
            axiosPrivate.interceptors.request.eject(requestIntercept);
            axiosPrivate.interceptors.response.eject(responseIntercept);
        }
    }, [auth, refresh])

    // возвращаем экземпляр axiosPrivate с применёнными перехватчиками
    return axiosPrivate;
}

export default useAxiosPrivate;