package example.micronaut.domain;

import java.io.Serializable;

import lombok.Data;

@Data
public class FuncRequest implements Serializable {
    private static final long serialVersionUID = 1L;

    /** 操作種別 */
    private String action;
    /** Game */
    private GameTable gameTablie;

}
