# 🛡️ Detecção de Atividades Maliciosas em Pacotes de Rede

Este projeto tem como objetivo comparar diferentes abordagens de detecção de tráfego malicioso em arquivos PCAP. Foram avaliadas três técnicas: inspeção profunda de pacotes com nDPI, sistema IDS/IPS com Suricata e filtragem estática baseada em regras simples (AoandonModel).

---

## 📂 Estrutura do Projeto
projetos/
├── main.py # Script principal com extração, validação e gráficos
├── pcaps/ # Diretório para armazenar arquivos PCAP (não incluso no Git)
├── resultados/ # Imagens geradas pelas análises comparativas
├── NUSW-NB15_GT.csv # Ground truth para validação (não incluso no Git)
├── .gitignore # Define arquivos ignorados pelo Git

---

## 🧪 Modelos Avaliados

| Modelo       | Tipo              | Descrição                                  |
|--------------|-------------------|---------------------------------------------|
| **nDPI**     | DPI (Deep Packet Inspection) | Classifica pacotes com base em categorias de risco ("Unsafe", "Dangerous") |
| **Suricata** | IDS/IPS baseado em regras     | Analisa pacotes e gera alertas a partir de regras padrão                |
| **Aoandon**  | Filtragem estática | Detecta pacotes com base em portas suspeitas (ex: 23, 3389)               |

---

## 📊 Métricas Coletadas

- Acurácia
- Matriz de confusão
- Uso de CPU
- Uso de memória
- Tempo de execução

---

## 🚀 Execução

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
2. Coloque os arquivos .pcap e NUSW-NB15_GT.csv nas pastas apropriadas (pcaps/ e raiz).

3. Execute o script principal:
   ```bash
   python main.py
   
📈 Resultados
Os resultados são exibidos no terminal e salvos como gráficos em resultados/.

⚠️ Observações
Arquivos grandes (*.pcap, *.csv) não estão incluídos neste repositório devido ao limite do GitHub.

Para testar localmente, adicione seus próprios arquivos PCAP em pcaps/ e atualize o caminho no script
