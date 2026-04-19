import { useEffect, useState } from 'react';
import useApi from './useApi';

export default function useDatasets() {
  const api = useApi();
  const [datasets, setDatasets] = useState({});

  useEffect(() => {
    api.get('/datasets').then(({ data }) => setDatasets(data)).catch(() => setDatasets({}));
  }, []);

  return datasets;
}
