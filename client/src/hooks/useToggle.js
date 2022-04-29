import useLocalStorage from './useLocalStorage';

const useToggle = (key, initValue) => {
  const [value, setValue] = useLocalStorage(key, initValue);

  const toggle = () => {
    setValue((prev) => !prev);
  };

  return [value, toggle];
};

export default useToggle;
