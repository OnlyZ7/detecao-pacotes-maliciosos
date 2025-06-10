# 🛡️ Detecção de Atividades Maliciosas em Pacotes de Rede

Este projeto tem como objetivo comparar diferentes abordagens para a detecção de tráfego malicioso em arquivos PCAP. Foram avaliadas três técnicas principais:

- **nDPI**: inspeção profunda de pacotes (Deep Packet Inspection)
- **Suricata**: sistema IDS/IPS baseado em regras
- **AoandonModel**: filtragem estática com base em portas suspeitas

---

## 📂 Estrutura do Projeto

```
projetos/
├── main.py               # Script principal com extração, validação e geração de gráficos
├── pcaps/                # Diretório com arquivos PCAP (não incluso no Git)
├── resultados/           # Diretório com os gráficos gerados
├── NUSW-NB15_GT.csv      # Ground truth para validação (não incluso no Git)
├── .gitignore            # Arquivos ignorados pelo Git
```

---

## 🧪 Modelos Avaliados

| Modelo       | Tipo                      | Descrição                                                                 |
|--------------|---------------------------|---------------------------------------------------------------------------|
| **nDPI**     | Deep Packet Inspection    | Classifica pacotes com base em categorias de risco como "Unsafe" e "Dangerous" |
| **Suricata** | IDS/IPS baseado em regras | Detecta tráfego malicioso com base em regras pré-definidas                |
| **Aoandon**  | Filtragem Estática        | Filtra pacotes com base em portas específicas (ex: 23, 3389)              |

---

## 📊 Métricas Coletadas

- Acurácia
- Matriz de confusão
- Uso de CPU
- Uso de memória
- Tempo de execução

---

## 🚀 Como Executar

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

2. Adicione os arquivos:
   - Coloque os arquivos `.pcap` na pasta `pcaps/`
   - Coloque o arquivo `NUSW-NB15_GT.csv` na raiz do projeto

3. Execute o script principal:
   ```bash
   python main.py
   ```

---

## 📈 Resultados

- Os resultados serão exibidos no terminal
- Os gráficos serão salvos na pasta `resultados/`

---

## ⚠️ Observações

- Arquivos grandes como `.pcap` e `.csv` **não estão incluídos no repositório** devido às limitações do GitHub.
- Para reproduzir os experimentos, utilize seus próprios arquivos `.pcap` e um ground truth compatível.

---

## 📘 Licença

Este projeto é acadêmico e livre para uso educacional.
